/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include "InstructionLifter.h"

#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/HelperMacro.h"
#include "remill/BC/InstructionLifter.h"

#include <cstdint>
#include <glog/logging.h>
#include <type_traits>

namespace remill {

namespace {

// Try to find the function that implements this semantics.
llvm::Function *GetInstructionFunction(llvm::Module *module, std::string_view function) {
  std::stringstream ss;
  ss << "ISEL_" << function;
  auto isel_name = ss.str();

  auto isel = FindGlobaVariable(module, isel_name);
  if (!isel) {
    return nullptr;  // Falls back on `UNIMPLEMENTED_INSTRUCTION`.
  }

  if (!isel->isConstant() || !isel->hasInitializer()) {
    LOG(FATAL) << "Expected a `constexpr` variable as the function pointer for "
               << "instruction semantic function " << function << ": " << LLVMThingToString(isel);
  }

  auto sem = isel->getInitializer()->stripPointerCasts();
  return llvm::dyn_cast_or_null<llvm::Function>(sem);
}

}  // namespace

InstructionLifter::Impl::Impl(const Arch *arch_, const IntrinsicTable *intrinsics_)
    : arch(arch_),
      intrinsics(intrinsics_),
      word_type(remill::NthArgument(intrinsics->jump, remill::kPCArgNum)->getType()),
      runtime_ptr_type(
          remill::NthArgument(intrinsics->jump, remill::kRuntimePointerArgNum)->getType()),
      module(intrinsics->async_hyper_call->getParent()),
      invalid_instruction(GetInstructionFunction(module, kInvalidInstructionISelName)),
      unsupported_instruction(GetInstructionFunction(module, kUnsupportedInstructionISelName)) {

  CHECK(invalid_instruction != nullptr) << kInvalidInstructionISelName << " doesn't exist";

  CHECK(unsupported_instruction != nullptr) << kUnsupportedInstructionISelName << " doesn't exist";
}

InstructionLifter::~InstructionLifter(void) {}

InstructionLifter::InstructionLifter(const Arch *arch_, const IntrinsicTable *intrinsics_)
    : impl(new Impl(arch_, intrinsics_)),
      debug_memory_value_change_name("debug_memory_value_change"),
      debug_insn_name("debug_insn") {}

// Lift a single instruction into a basic block. `is_delayed` signifies that
// this instruction will execute within the delay slot of another instruction.
LiftStatus InstructionLifterIntf::LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                                                BBRegInfoNode *bb_reg_info_node, bool is_delayed) {
  return LiftIntoBlock(inst, block, NthArgument(block->getParent(), kStatePointerArgNum),
                       bb_reg_info_node, is_delayed);
}

// Lift a single instruction into a basic block.
LiftStatus InstructionLifter::LiftIntoBlock(Instruction &arch_inst, llvm::BasicBlock *block,
                                            llvm::Value *state_ptr, BBRegInfoNode *bb_reg_info_node,
                                            bool is_delayed) {
  llvm::Function *const func = block->getParent();
  llvm::Module *const module = func->getParent();
  llvm::Function *isel_func = nullptr;
  auto status = kLiftedInstruction;


  // Cache invalidation.
  if (func != impl->last_func) {
    impl->reg_ptr_cache.clear();
    impl->last_func = func;

    CHECK_EQ(impl->module, module) << "InstructionLifter isn't using the correct module!";
  }

  if (arch_inst.IsValid()) {
    isel_func = GetInstructionFunction(module, arch_inst.function);
  } else {
    isel_func = impl->invalid_instruction;
    arch_inst.operands.clear();
    status = kLiftedInvalidInstruction;
    return status;
  }

  if (!isel_func) {
    isel_func = impl->unsupported_instruction;
    arch_inst.operands.clear();
    status = kLiftedUnsupportedInstruction;
    printf("[Bug] Unsupported instruction at address: 0x%08lx (SemanticsFunction), instForm: %s\n",
           arch_inst.pc, arch_inst.function.c_str());
    return status;
  }

  // If this instruction appears within a delay slot, then we're going to assume
  // that the prior instruction updated `PC` to the target of the CTI, and that
  // the value in `NEXT_PC` on entry to this instruction represents the actual
  // address of this instruction, so we'll swap `PC` and `NEXT_PC`.
  //
  // TODO(pag): An alternate approach may be to call some kind of `DELAY_SLOT`
  //            semantics function.
  if (is_delayed) {
    LOG(FATAL) << "Unexpected to enter the `is_delayed`.";
    // llvm::Value *temp_args[] = {ir.CreateLoad(impl->memory_ptr_type, mem_ptr_ref)};
    // ir.CreateStore(ir.CreateCall(impl->intrinsics->delay_slot_begin, temp_args), mem_ptr_ref);
  }

  // Begin an atomic block.
  // (FIXME) In the current design, we don't consider the atomic instructions.
  if (arch_inst.is_atomic_read_modify_write) {
    // llvm::Value *temp_args[] = {ir.CreateLoad(impl->memory_ptr_type, mem_ptr_ref)};
    // ir.CreateStore(ir.CreateCall(impl->intrinsics->atomic_begin, temp_args), mem_ptr_ref);
  }

  // Lift every operand of the target instruction.
  if (arch_inst.lift_config.target_elf_arch == kArchAArch64LittleEndian) {
    LiftAArch64EveryOperand(arch_inst, block, state_ptr, isel_func, bb_reg_info_node);
  } else if (arch_inst.lift_config.target_elf_arch == kArchAMD64) {
    LiftX86EveryOperand(arch_inst, block, state_ptr, isel_func, bb_reg_info_node);
  }

  // End an atomic block.
  // (FIXME) In the current design, we don't consider the atomic instructions.
  if (arch_inst.is_atomic_read_modify_write) {
    // llvm::Value *temp_args[] = {ir.CreateLoad(impl->memory_ptr_type, mem_ptr_ref)};
    // ir.CreateStore(ir.CreateCall(impl->intrinsics->atomic_end, temp_args), mem_ptr_ref);
  }

  // Restore the true target of the delayed branch.
  if (is_delayed) {

    // This is the delayed update of the program counter.
    // ir.CreateStore(next_pc, pc_ref);

    // We don't know what the `NEXT_PC` is going to be because of the next
    // instruction size is unknown (really, it's likely to be
    // `arch->MaxInstructionSize()`), and for normal instructions, before they
    // are lifted, we do the `PC = NEXT_PC + size`, so this is fine.
    // ir.CreateStore(next_pc, next_pc_ref);
    LOG(FATAL) << "Unexpected to enter the `is_delayed`.";
    // llvm::Value *temp_args[] = {ir.CreateLoad(impl->memory_ptr_type, mem_ptr_ref)};
    // ir.CreateStore(ir.CreateCall(impl->intrinsics->delay_slot_end, temp_args), mem_ptr_ref);
  }

  /* append `debug_memory_value_change` function call */
#if defined(LIFT_MEMORY_VALUE_CHANGE)
  llvm::IRBuilder<> __debug_ir(block);
  auto _debug_memory_value_change_fn = module->getFunction(debug_memory_value_change_name);
  auto [runtime_manager_ptr, _] = LoadRegAddress(block, state_ptr, kRuntimeVariableName);
  __debug_ir.CreateCall(
      _debug_memory_value_change_fn,
      {__debug_ir.CreateLoad(llvm::Type::getInt64PtrTy(module->getContext()), runtime_manager_ptr),
       llvm::ConstantInt::get(llvm::Type::getInt64Ty(module->getContext()), arch_inst.pc)});
#endif

  return status;
}

// Load the address of a register.
std::pair<llvm::Value *, llvm::Type *>
InstructionLifter::LoadRegAddress(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                  std::string_view reg_name_, bool is_global) const {
  const auto func = block->getParent();
  const auto module = func->getParent();

  // Invalidate the cache.
  if (func != impl->last_func) {
    impl->reg_ptr_cache.clear();
    impl->last_func = func;

    CHECK_EQ(func->getParent(), impl->module);
  }

  std::string reg_name(reg_name_.data(), reg_name_.size());
  auto [reg_ptr_it, added] = impl->reg_ptr_cache.emplace(
      std::move(reg_name), std::pair<llvm::Value *, llvm::Type *>{nullptr, nullptr});

  if (reg_ptr_it->second.first) {
    (void) added;
    return reg_ptr_it->second;
  }

  auto reg = impl->arch->RegisterByName(reg_name_);

  // It's already a variable in the function.
  const auto [var_ptr, var_ptr_type] = FindVarInFunction(func, reg_name_, true, is_global);
  if (var_ptr) {
    auto ty = var_ptr_type;
    //NOTE(Ian) for stuff like NEXT_PC existing in the block we arent going to have reg type info, im not sure i like pulling it from var_ptr_type regardles. Not sure what to do about it
    if (reg) {
      ty = reg->type;
    }
    reg_ptr_it->second = {var_ptr, ty};
    return reg_ptr_it->second;
  }

  // It's a register known to this architecture, so go and build a GEP to it
  // right now. We'll try to be careful about the placement of the actual
  // indexing instructions so that they always follow the definition of the
  // state pointer, and thus are most likely to dominate all future uses.
  if (reg) {
    llvm::Value *reg_ptr = nullptr;

    // The state pointer is an argument.
    if (auto state_arg = llvm::dyn_cast<llvm::Argument>(state_ptr); state_arg) {
      DCHECK_EQ(state_arg->getParent(), block->getParent());
      auto &target_block = block->getParent()->getEntryBlock();
      llvm::IRBuilder<> ir(&target_block, target_block.getFirstInsertionPt());
      reg_ptr = reg->AddressOf(state_ptr, ir);

      // The state pointer is an instruction, likely an `AllocaInst`.
    } else if (auto state_inst = llvm::dyn_cast<llvm::Instruction>(state_ptr); state_inst) {
      llvm::IRBuilder<> ir(state_inst);
      reg_ptr = reg->AddressOf(state_ptr, ir);

      // The state pointer is a constant, likely an `llvm::GlobalVariable`.
    } else if (auto state_const = llvm::dyn_cast<llvm::Constant>(state_ptr); state_const) {
      auto &target_block = block->getParent()->getEntryBlock();
      llvm::IRBuilder<> ir(&target_block, target_block.getFirstInsertionPt());
      reg_ptr = reg->AddressOf(state_ptr, ir);

      // Not sure.
    } else {
      LOG(FATAL) << "Unsupported value type for the State pointer: "
                 << LLVMThingToString(state_ptr);
    }

#if defined(SIMPLE_OPT)
    // Copy the global pointer to the local variable.
    reg_ptr = GetLocalRegAddress(&func->getEntryBlock(), reg->name, reg_ptr, reg->type);
#endif

    reg_ptr_it->second = {reg_ptr, reg->type};
    return reg_ptr_it->second;
  }

  LOG(FATAL) << "This point must not be reached in the current implementation. reg_name: "
             << reg_name_;

  // Try to find it as a global variable.
  if (auto gvar = module->getGlobalVariable(reg_name)) {
    return {gvar, gvar->getValueType()};
  }

  // Invent a fake one and keep going.
  std::stringstream unk_var;
  unk_var << "__remill_unknown_register_" << reg_name;
  auto unk_var_name = unk_var.str();
  if (auto var = module->getGlobalVariable(unk_var_name)) {
    return {var, var->getValueType()};
  }

  // TODO(pag): Eventually refactor into a higher-level issue, perhaps a
  //            a hyper call to read an unknown register, or a lifting failure,
  //            with a more elaborate status value returned.
  LOG(FATAL) << "Could not locate variable or register " << reg_name_;

  return {new llvm::GlobalVariable(*module, impl->word_type, false,
                                   llvm::GlobalValue::ExternalLinkage,
                                   llvm::UndefValue::get(impl->word_type), unk_var_name),
          impl->word_type};
}

llvm::Value *
InstructionLifter::GetLocalRegAddress(llvm::BasicBlock *entry_bb, std::string_view reg_name,
                                      llvm::Value *tg_reg_ptr, llvm::Type *tg_reg_type) const {

  auto trmi = entry_bb->getTerminator();
  llvm::IRBuilder<> ir(trmi);

  std::string lc_reg_name = std::string(reg_name) + "_Lc";
  auto reg_ptr = ir.CreateAlloca(tg_reg_type, nullptr, lc_reg_name);
  auto tg_reg_val = ir.CreateLoad(tg_reg_type, tg_reg_ptr);
  ir.CreateStore(tg_reg_val, reg_ptr);

  return reg_ptr;
}

// Clear out the cache of the current register values/addresses loaded.
void InstructionLifter::ClearCache(void) const {
  impl->reg_ptr_cache.clear();
  impl->last_func = nullptr;
}

// Load the value of a register.
llvm::Value *InstructionLifter::LoadRegValue(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                             std::string_view reg_name) const {
  auto [ptr, ptr_ty] = LoadRegAddress(block, state_ptr, reg_name);
  CHECK_NOTNULL(ptr);
  return new llvm::LoadInst(ptr_ty, ptr, llvm::Twine::createNull(), block);
}

llvm::Value *
InstructionLifter::LoadRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                          std::string_view reg_name, llvm::Instruction *instBefore,
                                          std::string var_name) const {
  auto [ptr, ptr_ty] = LoadRegAddress(block, state_ptr, reg_name);
  CHECK_NOTNULL(ptr);
  return new llvm::LoadInst(ptr_ty, ptr, var_name, instBefore);
}

// Store the value of a register (Assume that the store_value already has been casted).
llvm::Instruction *
InstructionLifter::StoreRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                           std::string_view reg_name, llvm::Value *stored_value,
                                           llvm::Instruction *instBefore) const {
  auto [ptr, ptr_ty] = LoadRegAddress(block, state_ptr, reg_name);
  CHECK_NOTNULL(ptr);
  return new llvm::StoreInst(stored_value, ptr, instBefore);
}

// Return a register value, or zero.
llvm::Value *
InstructionLifter::LoadWordRegValOrZero(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                        std::string_view reg_name, llvm::ConstantInt *zero) {

  if (reg_name.empty()) {
    return zero;
  }

  auto val = LoadRegValue(block, state_ptr, reg_name);
  auto val_type = llvm::dyn_cast_or_null<llvm::IntegerType>(val->getType());
  auto word_type = zero->getType();

  CHECK(val_type) << "Register " << reg_name << " expected to be an integer.";

  auto val_size = val_type->getBitWidth();
  auto word_size = word_type->getBitWidth();
  CHECK_LE(val_size, word_size) << "Register " << reg_name << " expected to be no larger than the "
                                << "machine word size (" << word_type->getBitWidth() << " bits).";

  if (val_size < word_size) {
    val = new llvm::ZExtInst(val, word_type, llvm::Twine::createNull(), block);
  }

  return val;
}

llvm::Value *InstructionLifter::LiftShiftRegisterOperand(Instruction &inst, llvm::BasicBlock *block,
                                                         llvm::Value *state_ptr,
                                                         llvm::Argument *arg, Operand &op) {

  llvm::Function *func = block->getParent();
  llvm::Module *module = func->getParent();
  auto &context = module->getContext();
  auto &arch_reg = op.shift_reg.reg;

  auto arg_type = arg->getType();
  CHECK(arg_type->isIntegerTy()) << "Expected " << arch_reg.name << " to be an integral type "
                                 << "for instruction at " << std::hex << inst.pc;

  const llvm::DataLayout data_layout(module);
  auto reg = LoadRegValue(block, state_ptr, arch_reg.name);
  auto reg_type = reg->getType();
  auto reg_size = data_layout.getTypeSizeInBits(reg_type).getFixedValue();
  auto op_type = llvm::Type::getIntNTy(context, op.size);

  const uint64_t zero = 0;
  const uint64_t one = 1;
  const uint64_t shift_size = op.shift_reg.shift_size;

  const auto shift_val = llvm::ConstantInt::get(op_type, shift_size);

  llvm::IRBuilder<> ir(block);

  auto curr_size = reg_size;
  if (Operand::ShiftRegister::kExtendInvalid != op.shift_reg.extend_op) {

    auto extract_type = llvm::Type::getIntNTy(context, op.shift_reg.extract_size);

    if (reg_size > op.shift_reg.extract_size) {
      curr_size = op.shift_reg.extract_size;
      reg = ir.CreateTrunc(reg, extract_type);

    } else {
      CHECK_EQ(reg_size, op.shift_reg.extract_size)
          << "Invalid extraction size. Can't extract " << op.shift_reg.extract_size
          << " bits from a " << reg_size << "-bit value in operand " << op.Serialize()
          << " of instruction at " << std::hex << inst.pc;
    }

    if (op.size > op.shift_reg.extract_size) {
      switch (op.shift_reg.extend_op) {
        case Operand::ShiftRegister::kExtendSigned:
          reg = ir.CreateSExt(reg, op_type);
          curr_size = op.size;
          break;
        case Operand::ShiftRegister::kExtendUnsigned:
          reg = ir.CreateZExt(reg, op_type);
          curr_size = op.size;
          break;
        default:
          LOG(FATAL) << "Invalid extend operation type for instruction at " << std::hex << inst.pc;
          break;
      }
    }
  }

  CHECK_LE(curr_size, op.size);

  if (curr_size < op.size) {
    reg = ir.CreateZExt(reg, op_type);
    curr_size = op.size;
  }

  if (Operand::ShiftRegister::kShiftInvalid != op.shift_reg.shift_op) {

    CHECK_LT(shift_size, op.size) << "Shift of size " << shift_size
                                  << " is wider than the base register size in shift register in "
                                  << inst.Serialize();

    switch (op.shift_reg.shift_op) {

      // Left shift.
      case Operand::ShiftRegister::kShiftLeftWithZeroes: reg = ir.CreateShl(reg, shift_val); break;

      // Masking shift left.
      case Operand::ShiftRegister::kShiftLeftWithOnes: {
        const auto mask_val = llvm::ConstantInt::get(reg_type, ~((~zero) << shift_size));
        reg = ir.CreateOr(ir.CreateShl(reg, shift_val), mask_val);
        break;
      }

      // Logical right shift.
      case Operand::ShiftRegister::kShiftUnsignedRight: reg = ir.CreateLShr(reg, shift_val); break;

      // Arithmetic right shift.
      case Operand::ShiftRegister::kShiftSignedRight: reg = ir.CreateAShr(reg, shift_val); break;

      // Rotate left.
      case Operand::ShiftRegister::kShiftLeftAround: {
        const uint64_t shr_amount = (~shift_size + one) & (op.size - one);
        const auto shr_val = llvm::ConstantInt::get(op_type, shr_amount);
        const auto val1 = ir.CreateLShr(reg, shr_val);
        const auto val2 = ir.CreateShl(reg, shift_val);
        reg = ir.CreateOr(val1, val2);
        break;
      }

      // Rotate right.
      case Operand::ShiftRegister::kShiftRightAround: {
        const uint64_t shl_amount = (~shift_size + one) & (op.size - one);
        const auto shl_val = llvm::ConstantInt::get(op_type, shl_amount);
        const auto val1 = ir.CreateLShr(reg, shift_val);
        const auto val2 = ir.CreateShl(reg, shl_val);
        reg = ir.CreateOr(val1, val2);
        break;
      }

      case Operand::ShiftRegister::kShiftInvalid: break;
    }
  }

  // if (word_size > op.size) {
  //   reg = ir.CreateZExt(reg, impl->word_type);
  // } else {
  //   CHECK_EQ(word_size, op.size) << "Final size of operand " << op.Serialize() << " is " << op.size
  //                                << " bits, but address size is " << word_size;
  // }

  return reg;
}

namespace {

static llvm::Type *IntendedArgumentType(llvm::Argument *arg) {
  for (auto user : arg->users()) {
    if (auto cast_inst = llvm::dyn_cast<llvm::IntToPtrInst>(user)) {
      return cast_inst->getType();
    }
  }
  return arg->getType();
}

static llvm::Value *ConvertToIntendedType(Instruction &inst, Operand &op, llvm::BasicBlock *block,
                                          llvm::Value *val, llvm::Type *intended_type) {
  auto val_type = val->getType();
  if (val->getType() == intended_type) {
    return val;
  } else if (auto val_ptr_type = llvm::dyn_cast<llvm::PointerType>(val_type)) {
    if (intended_type->isPointerTy() || intended_type->isVectorTy()) {
      return new llvm::BitCastInst(val, intended_type, val->getName(), block);
    } else if (intended_type->isIntegerTy()) {
      return new llvm::PtrToIntInst(val, intended_type, val->getName(), block);
    }
  } else if (val_type->isFloatingPointTy()) {
    if (intended_type->isIntegerTy() || intended_type->isVectorTy()) {
      return new llvm::BitCastInst(val, intended_type, val->getName(), block);
    }
  } else if (val_type->isVectorTy()) {
    const llvm::DataLayout data_layout(block->getModule());
    auto val_type = val->getType();
    CHECK(data_layout.getTypeAllocSizeInBits(val_type) ==
          data_layout.getTypeAllocSizeInBits(intended_type))
        << "must be equal. intended_type: " << LLVMThingToString(intended_type)
        << ", val_type: " << LLVMThingToString(val_type) << " at address: 0x" << std::hex << inst.pc
        << " " << inst.function;

    return new llvm::BitCastInst(val, intended_type, val->getName(), block);
  }

  LOG(FATAL) << "Unable to convert value " << LLVMThingToString(val)
             << " (val type: " << LLVMThingToString(val_type) << ") "
             << " to intended argument type " << LLVMThingToString(intended_type) << " for operand "
             << op.Serialize() << " of instruction " << inst.Serialize();

  return nullptr;
}

}  // namespace

// Load a register operand. This deals uniformly with write- and read-operands
// for registers. In the case of write operands, the argument type is always
// a pointer. In the case of read operands, the argument type is sometimes
// a pointer (e.g. when passing a vector to an instruction semantics function).
llvm::Value *InstructionLifter::LiftRegisterOperand(Instruction &inst, llvm::BasicBlock *block,
                                                    llvm::Value *state_ptr, llvm::Argument *arg,
                                                    Operand &op) {

  llvm::Function *func = block->getParent();
  llvm::Module *module = func->getParent();
  auto &context = func->getContext();
  auto &arch_reg = op.reg;

  const auto real_arg_type = arg->getType();

  // LLVM on AArch64 and on amd64 Windows converts things like `RnW<uint64_t>`,
  // which is a struct containing a `uint64_t *`, into a `uintptr_t` when they
  // are being passed as arguments.
  auto arg_type = IntendedArgumentType(arg);

  if (llvm::isa<llvm::PointerType>(arg_type)) {
    auto [val, val_type] = LoadRegAddress(block, state_ptr, arch_reg.name);
    return ConvertToIntendedType(inst, op, block, val, real_arg_type);

  } else {
    CHECK(arg_type->isIntegerTy() || arg_type->isFloatingPointTy() || arg_type->isVectorTy())
        << "arg_type: " << LLVMThingToString(arg_type) << ", Expected " << arch_reg.name
        << " to be an integral or float type or vector type"
        << "for instruction at 0x" << std::hex << inst.pc;

    if (31 == op.reg.number) {
      if ("XZR" == op.reg.name) {
        return llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0);
      } else if ("WZR" == op.reg.name) {
        return llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), 0);
      }
    }

    auto val = LoadRegValue(block, state_ptr, arch_reg.name);

    const llvm::DataLayout data_layout(module);
    auto val_type = val->getType();
    auto val_size = data_layout.getTypeAllocSizeInBits(val_type);
    auto arg_size = data_layout.getTypeAllocSizeInBits(arg_type);

    if (val_size < arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy()) << "Expected " << arch_reg.name << " to be an integral type "
                                       << "for instruction at " << std::hex << inst.pc;

        val = new llvm::ZExtInst(val, arg_type, llvm::Twine::createNull(), block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << arch_reg.name << " to be a floating point type "
            << "for instruction at " << std::hex << inst.pc;

        val = new llvm::FPExtInst(val, arg_type, llvm::Twine::createNull(), block);
      }

    } else if (val_size > arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy()) << "Expected " << arch_reg.name << " to be an integral type "
                                       << "for instruction at " << std::hex << inst.pc;

        val = new llvm::TruncInst(val, arg_type, llvm::Twine::createNull(), block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << arch_reg.name
            << " to be a floating point type (Actual: " << LLVMThingToString(val_type) << ") "
            << "for instruction at " << std::hex << inst.pc;

        val = new llvm::FPTruncInst(val, arg_type, llvm::Twine::createNull(), block);
      }
    }

    return ConvertToIntendedType(inst, op, block, val, real_arg_type);
  }
}

// Lift an immediate operand.
llvm::Value *InstructionLifter::LiftImmediateOperand(Instruction &inst, llvm::BasicBlock *,
                                                     llvm::Argument *arg, Operand &arch_op) {
  if (arg->getType()->isIntegerTy()) {
    return llvm::ConstantInt::get(arg->getType(), arch_op.imm.val, arch_op.imm.is_signed);
  } else if (arg->getType()->isFloatTy()) {
    auto float_val = *reinterpret_cast<float *>(&arch_op.imm.val);
    return llvm::ConstantFP::get(arg->getType(), float_val);
  } else if (arg->getType()->isDoubleTy()) {
    auto double_val = *reinterpret_cast<double *>(&arch_op.imm.val);
    return llvm::ConstantFP::get(arg->getType(), double_val);
  }

  else {
    LOG(FATAL) << "Unexpected type of the Immediate. arg type: "
               << LLVMThingToString(arg->getType());
  }
}

// Lift an expression operand.
llvm::Value *InstructionLifter::LiftExpressionOperand(Instruction &inst, llvm::BasicBlock *block,
                                                      llvm::Value *state_ptr, llvm::Argument *arg,
                                                      Operand &op) {
  auto val = LiftExpressionOperandRec(inst, block, state_ptr, arg, op.expr);
  llvm::Function *func = block->getParent();
  llvm::Module *module = func->getParent();
  const auto real_arg_type = arg->getType();

  // LLVM on AArch64 and on amd64 Windows converts things like `RnW<uint64_t>`,
  // which is a struct containing a `uint64_t *`, into a `uintptr_t` when they
  // are being passed as arguments.
  auto arg_type = IntendedArgumentType(arg);

  if (llvm::isa<llvm::PointerType>(arg_type)) {
    return ConvertToIntendedType(inst, op, block, val, real_arg_type);

  } else {
    CHECK(arg_type->isIntegerTy() || arg_type->isFloatingPointTy())
        << "Expected " << op.Serialize() << " to be an integral or float type "
        << "for instruction at " << std::hex << inst.pc;

    const llvm::DataLayout data_layout(module);
    auto val_type = val->getType();
    auto val_size = data_layout.getTypeAllocSizeInBits(val_type);
    auto arg_size = data_layout.getTypeAllocSizeInBits(arg_type);
    const auto word_size = impl->arch->address_size;

    if (val_size < arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy())
            << "Expected " << op.Serialize() << " to be an integral type "
            << "for instruction at " << std::hex << inst.pc;

        CHECK(word_size == arg_size) << "Expected integer argument to be machine word size ("
                                     << word_size << " bits) but is is " << arg_size << " instead "
                                     << "in instruction at " << std::hex << inst.pc;

        val = new llvm::ZExtInst(val, impl->word_type, "", block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << op.Serialize() << " to be a floating point type "
            << "for instruction at " << std::hex << inst.pc;

        val = new llvm::FPExtInst(val, arg_type, "", block);
      }

    } else if (val_size > arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy())
            << "Expected " << op.Serialize() << " to be an integral type "
            << "for instruction at " << std::hex << inst.pc;

        CHECK(word_size == arg_size) << "Expected integer argument to be machine word size ("
                                     << word_size << " bits) but is is " << arg_size << " instead "
                                     << "in instruction at " << std::hex << inst.pc;

        val = new llvm::TruncInst(val, arg_type, "", block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << op.Serialize() << " to be a floating point type "
            << "for instruction at " << std::hex << inst.pc;

        val = new llvm::FPTruncInst(val, arg_type, "", block);
      }
    }

    return ConvertToIntendedType(inst, op, block, val, real_arg_type);
  }
}

// Lift an expression operand.
llvm::Value *InstructionLifter::LiftExpressionOperandRec(Instruction &inst, llvm::BasicBlock *block,
                                                         llvm::Value *state_ptr,
                                                         llvm::Argument *arg,
                                                         const OperandExpression *op) {
  if (auto llvm_op = std::get_if<LLVMOpExpr>(op)) {
    auto lhs = LiftExpressionOperandRec(inst, block, state_ptr, nullptr, llvm_op->op1);
    llvm::Value *rhs = nullptr;
    if (llvm_op->op2) {
      rhs = LiftExpressionOperandRec(inst, block, state_ptr, nullptr, llvm_op->op2);
    }
    llvm::IRBuilder<> ir(block);
    switch (llvm_op->llvm_opcode) {
      case llvm::Instruction::Add: return ir.CreateAdd(lhs, rhs);
      case llvm::Instruction::Sub: return ir.CreateSub(lhs, rhs);
      case llvm::Instruction::Mul: return ir.CreateMul(lhs, rhs);
      case llvm::Instruction::Shl: return ir.CreateShl(lhs, rhs);
      case llvm::Instruction::LShr: return ir.CreateLShr(lhs, rhs);
      case llvm::Instruction::AShr: return ir.CreateAShr(lhs, rhs);
      case llvm::Instruction::ZExt: return ir.CreateZExt(lhs, op->type);
      case llvm::Instruction::SExt: return ir.CreateSExt(lhs, op->type);
      case llvm::Instruction::Trunc: return ir.CreateTrunc(lhs, op->type);
      case llvm::Instruction::And: return ir.CreateAnd(lhs, rhs);
      case llvm::Instruction::Or: return ir.CreateOr(lhs, rhs);
      case llvm::Instruction::URem: return ir.CreateURem(lhs, rhs);
      case llvm::Instruction::Xor: return ir.CreateXor(lhs, rhs);
      default:
        LOG(FATAL) << "Invalid Expression "
                   << llvm::Instruction::getOpcodeName(llvm_op->llvm_opcode);
        return nullptr;
    }
  } else if (auto reg_op = std::get_if<const Register *>(op)) {
    if (!arg || !llvm::isa<llvm::PointerType>(arg->getType())) {
      return LoadRegValue(block, state_ptr, (*reg_op)->name);
    } else {
      return LoadRegAddress(block, state_ptr, (*reg_op)->name).first;
    }

  } else if (auto ci_op = std::get_if<llvm::Constant *>(op)) {
    return *ci_op;

  } else if (auto str_op = std::get_if<std::string>(op)) {
    if (!arg || !llvm::isa<llvm::PointerType>(arg->getType())) {
      return LoadRegValue(block, state_ptr, *str_op);
    } else {
      return LoadRegAddress(block, state_ptr, *str_op).first;
    }
  } else {
    LOG(FATAL) << "Uninitialized Operand Expression";
    return nullptr;
  }
}

// Zero-extend a value to be the machine word size.
llvm::Value *InstructionLifter::LiftAddressOperand(Instruction &inst, llvm::BasicBlock *block,
                                                   llvm::Value *state_ptr, llvm::Argument *,
                                                   Operand &op) {
  auto &arch_addr = op.addr;
  const auto word_type = llvm::dyn_cast<llvm::IntegerType>(impl->word_type);
  const auto zero = llvm::ConstantInt::get(word_type, 0, false);
  const auto word_size = impl->arch->address_size;

  CHECK(word_size >= arch_addr.base_reg.size)
      << "Memory base register " << arch_addr.base_reg.name << "for instruction at " << std::hex
      << inst.pc << " is wider than the machine word size.";

  CHECK(word_size >= arch_addr.index_reg.size)
      << "Memory index register " << arch_addr.base_reg.name << "for instruction at " << std::hex
      << inst.pc << " is wider than the machine word size.";

  if ("PC" == arch_addr.base_reg.name) {
    return llvm::ConstantInt::get(word_type,
                                  static_cast<uint64_t>(inst.pc + arch_addr.displacement));
  }

  if ("RIP" == arch_addr.base_reg.name) {
    return llvm::ConstantInt::get(word_type,
                                  static_cast<uint64_t>(inst.pc + arch_addr.displacement));
  }

  // x86-64 RIP addressing mode uses the next instruction RIP.
  if ("NEXT_PC" == arch_addr.base_reg.name) {
    return llvm::ConstantInt::get(
        word_type, static_cast<uint64_t>(inst.pc + inst.bytes.size() + arch_addr.displacement));
  }

  auto addr = LoadWordRegValOrZero(block, state_ptr, arch_addr.base_reg.name, zero);
  auto index = LoadWordRegValOrZero(block, state_ptr, arch_addr.index_reg.name, zero);
  auto scale = llvm::ConstantInt::get(word_type, static_cast<uint64_t>(arch_addr.scale), true);
  auto segment = LoadWordRegValOrZero(block, state_ptr, arch_addr.segment_base_reg.name, zero);

  llvm::IRBuilder<> ir(block);

  if (zero != index) {
    addr = ir.CreateAdd(addr, ir.CreateMul(index, scale));
  }

  if (arch_addr.displacement) {
    if (0 < arch_addr.displacement) {
      addr = ir.CreateAdd(
          addr, llvm::ConstantInt::get(word_type, static_cast<uint64_t>(arch_addr.displacement)));
    } else {
      addr = ir.CreateSub(
          addr, llvm::ConstantInt::get(word_type, static_cast<uint64_t>(-arch_addr.displacement)));
    }
  }

  // Compute the segmented address.
  if (zero != segment) {
    addr = ir.CreateAdd(addr, segment);
  }

  // Memory address is smaller than the machine word size (e.g. 32-bit address
  // used in 64-bit).
  if (arch_addr.address_size < word_size) {
    auto addr_type =
        llvm::Type::getIntNTy(block->getContext(), static_cast<unsigned>(arch_addr.address_size));

    addr = ir.CreateZExt(ir.CreateTrunc(addr, addr_type), word_type);
  }

  return addr;
}

// Lift an operand for use by the instruction.
llvm::Value *InstructionLifter::LiftOperand(Instruction &inst, llvm::BasicBlock *block,
                                            llvm::Value *state_ptr, llvm::Argument *arg,
                                            Operand &arch_op) {
  auto arg_type = arg->getType();
  switch (arch_op.type) {
    case Operand::kTypeInvalid:
      LOG(FATAL) << "Decode error! Cannot lift invalid operand.";
      return nullptr;

    case Operand::kTypeShiftRegister:
      CHECK(Operand::kActionRead == arch_op.action) << "Can't write to a shift register operand "
                                                    << "for instruction at " << std::hex << inst.pc;

      return LiftShiftRegisterOperand(inst, block, state_ptr, arg, arch_op);

    case Operand::kTypeRegister:
      if (arch_op.size != arch_op.reg.size) {
        LOG(FATAL) << "Operand size and register size must match for register " << arch_op.reg.name
                   << " in instruction " << inst.Serialize();
      }
      return LiftRegisterOperand(inst, block, state_ptr, arg, arch_op);

    case Operand::kTypeImmediate: return LiftImmediateOperand(inst, block, arg, arch_op);

    case Operand::kTypeAddress:
      if (arg_type != impl->word_type) {
        LOG(FATAL) << "Expected that a memory operand should be represented by "
                   << "machine word type. Argument type is " << LLVMThingToString(arg_type)
                   << " and word type is " << LLVMThingToString(impl->word_type)
                   << " in instruction at 0x" << std::hex << inst.pc;
      }

      return LiftAddressOperand(inst, block, state_ptr, arg, arch_op);

    case Operand::kTypeExpression:
    case Operand::kTypeRegisterExpression:
    case Operand::kTypeImmediateExpression:
    case Operand::kTypeAddressExpression:
      return LiftExpressionOperand(inst, block, state_ptr, arg, arch_op);
  }

  LOG(FATAL) << "Got a unknown operand type of " << static_cast<int>(arch_op.type)
             << " in instruction at " << std::hex << inst.pc;

  return nullptr;
}

llvm::Type *InstructionLifter::GetWordType() {
  return this->impl->word_type;
}
llvm::Type *InstructionLifter::GetRuntimeType() {
  return this->impl->runtime_ptr_type;
}

const IntrinsicTable *InstructionLifter::GetIntrinsicTable() {
  return this->impl->intrinsics;
}

bool InstructionLifter::ArchHasRegByName(std::string name) {
  return this->impl->arch->RegisterByName(name) != nullptr;
}

}  // namespace remill
