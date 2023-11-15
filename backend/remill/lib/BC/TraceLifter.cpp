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

namespace {

using DecoderWorkList = std::set<uint64_t>;  // For ordering.

}  // namespace

class TraceLifter::Impl {
 public:
  Impl(const Arch *arch_, TraceManager *manager_);

  // Lift one or more traces starting from `addr`. Calls `callback` with each
  // lifted trace.
  bool Lift(uint64_t addr, const char* fn_name = "",
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

  // Set entry function pointer
  llvm::GlobalVariable *SetEntryPoint(std::string &entry_func_name);

  // Set entry PC
  llvm::GlobalVariable *SetEntryPC(uint64_t pc);

  // Define pre-refered function
  llvm::Function *DefinePreReferedFunction(std::string fun_name, std::string callee_fun_name, LLVMFunTypeIdent llvm_fn_ty_id);

  // Get pre-defined function (extern function is included)
  llvm::Function *GetDefinedFunction(std::string fun_name, std::string callee_fun_name, LLVMFunTypeIdent llvm_fn_ty_id);

  // Convert LLVMFunTypeIdent to llvm::FunctionType
  llvm::FunctionType *FunTypeID_2_FunType (LLVMFunTypeIdent llvm_fn_ty_id);

  // Set data sections
  llvm::GlobalVariable *SetDataSections(std::vector<BinaryLoader::ELFSection> &sections);

  /* Set ELF program header info */
  llvm::GlobalVariable *SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph);

  /* Set platform name */
  llvm::GlobalVariable *SetPlatform(const char *platform_name);

  /* Set lifted function pointer table */
  llvm::GlobalVariable *SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fun_map);

  /* Set control flow debug list */
  void SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &__control_flow_debug_list);
  
  /* Declare debug_state_machine function */
  llvm::Function *DeclareDebugStateMachine();

  /* Declare debug_pc function */
  llvm::Function *DeclareDebugPC();

  llvm::BasicBlock *GetOrCreateBlock(uint64_t block_pc) {
    auto &block = blocks[block_pc];
    if (!block) {
      block = llvm::BasicBlock::Create(context, "", func);
    }
    return block;
  }

  llvm::BasicBlock *GetOrCreateBranchTakenBlock(void) {
    inst_work_list.insert(inst.branch_taken_pc);
    return GetOrCreateBlock(inst.branch_taken_pc);
  }

  llvm::BasicBlock *GetOrCreateBranchNotTakenBlock(void) {
    CHECK(inst.branch_not_taken_pc != 0);
    inst_work_list.insert(inst.branch_not_taken_pc);
    return GetOrCreateBlock(inst.branch_not_taken_pc);
  }

  llvm::BasicBlock *GetOrCreateNextBlock(void) {
    inst_work_list.insert(inst.next_pc);
    return GetOrCreateBlock(inst.next_pc);
  }

  uint64_t PopTraceAddress(void) {
    auto trace_it = trace_work_list.begin();
    const auto trace_addr = *trace_it;
    trace_work_list.erase(trace_it);
    return trace_addr;
  }

  uint64_t PopInstructionAddress(void) {
    auto inst_it = inst_work_list.begin();
    const auto inst_addr = *inst_it;
    inst_work_list.erase(inst_it);
    return inst_addr;
  }

  const Arch *const arch;
  const remill::IntrinsicTable *intrinsics;
  llvm::Type *word_type;
  llvm::LLVMContext &context;
  llvm::Module *const module;
  const uint64_t addr_mask;
  TraceManager &manager;

  llvm::Function *func;
  llvm::BasicBlock *block;
  llvm::SwitchInst *switch_inst;
  const size_t max_inst_bytes;
  std::string inst_bytes;
  Instruction inst;
  Instruction delayed_inst;
  std::unordered_map<uint64_t, bool> control_flow_debug_list;
  DecoderWorkList trace_work_list;
  DecoderWorkList inst_work_list;
  std::map<uint64_t, llvm::BasicBlock *> blocks;
  std::string g_entry_func_name;
  std::string g_entry_pc_name;
  std::string data_sec_name_array_name;
  std::string data_sec_vma_array_name;
  std::string data_sec_size_array_name;
  std::string data_sec_bytes_array_name;
  std::string data_sec_num_name;
  std::string e_phent_name;
  std::string e_phnum_name;
  std::string e_ph_name;
  std::string g_platform_name;
  std::string g_addr_list_name;
  std::string g_fun_ptr_table_name;
  std::string debug_state_machine_name;
  std::string debug_pc_name;
};

TraceLifter::Impl::Impl(const Arch *arch_, TraceManager *manager_)
    : arch(arch_),
      intrinsics(arch->GetInstrinsicTable()),
      word_type(arch->AddressType()),
      context(word_type->getContext()),
      module(intrinsics->async_hyper_call->getParent()),
      addr_mask(arch->address_size >= 64 ? ~0ULL
                                         : (~0ULL >> arch->address_size)),
      manager(*manager_),
      func(nullptr),
      block(nullptr),
      switch_inst(nullptr),
      // TODO(Ian): The trace lfiter is not supporting contexts
      max_inst_bytes(arch->MaxInstructionSize(arch->CreateInitialContext())),
      g_entry_func_name("__g_entry_func"),
      g_entry_pc_name("__g_entry_pc"),
      data_sec_name_array_name("__g_data_sec_name_ptr_array"),
      data_sec_vma_array_name("__g_data_sec_vma_array"),
      data_sec_size_array_name("__g_data_sec_size_array"),
      data_sec_bytes_array_name("__g_data_sec_bytes_ptr_array"),
      data_sec_num_name("__g_data_sec_num"),
      e_phent_name("__g_e_phent"),
      e_phnum_name("__g_e_phnum"),
      e_ph_name("__g_e_ph"),
      g_platform_name("__g_platform_name"),
      g_addr_list_name("__g_fn_vmas"),
      g_fun_ptr_table_name("__g_fn_ptr_table"),
      debug_state_machine_name("debug_state_machine"),
      debug_pc_name("debug_pc") {

  inst_bytes.reserve(max_inst_bytes);
}

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

// Set entry function pointer
llvm::GlobalVariable *TraceLifter::Impl::SetEntryPoint(std::string &entry_func_name) {
    
  auto entry_func = module->getFunction(entry_func_name);
  // no defined entry function
  if (!entry_func) {
    printf("[ERROR] Entry function is not defined. func_name: %s\n", entry_func_name.c_str());
    abort();
  }
  auto g_entry_func = new llvm::GlobalVariable(
    *module, 
    entry_func->getType(),
    true, 
    llvm::GlobalVariable::ExternalLinkage, 
    entry_func, 
    g_entry_func_name
  );
  g_entry_func->setAlignment(llvm::MaybeAlign(8));
  
  return g_entry_func;
}

// Set entry pc
llvm::GlobalVariable *TraceLifter::Impl::SetEntryPC(uint64_t pc) {
  
  auto ty = llvm::Type::getInt64Ty(context);
  auto entry_pc = new llvm::GlobalVariable(
    *module,
    ty,
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantInt::get(ty, pc),
    g_entry_pc_name
  );
  entry_pc->setAlignment(llvm::MaybeAlign(8));
  
  return entry_pc;
}

// Define pre-referenced function
llvm::Function *TraceLifter::Impl::DefinePreReferedFunction(std::string fun_name, std::string callee_fun_name, LLVMFunTypeIdent llvm_fn_ty_id) {
  
  auto callee_fun = GetDefinedFunction(fun_name, callee_fun_name, llvm_fn_ty_id);

  // generate sub function
  llvm::Function *sub_fn;
  sub_fn = module->getFunction(fun_name);
  if (!sub_fn) {
    sub_fn = arch->DeclareLiftedFunction(fun_name, module);
  }
  // insert callee basic block
  auto *callee_bb = llvm::BasicBlock::Create(context, "entry", sub_fn);
  llvm::IRBuilder<> ir(callee_bb);
  std::vector<llvm::Value*> callee_args;
  for (size_t _arg_i = 0;_arg_i < sub_fn->arg_size();_arg_i++) {
    callee_args.emplace_back(sub_fn->getArg(_arg_i));
  }
  llvm::AllocaInst *mem_ptr_reg = ir.CreateAlloca(word_type, nullptr, kMemoryVariableName);
  mem_ptr_reg->setAlignment(llvm::Align(8));
  // if callee_fun return void, 
  if (callee_fun->getReturnType()->isVoidTy()) {
    ir.CreateStore(
      llvm::Constant::getNullValue(word_type),
      mem_ptr_reg
    );
    ir.CreateCall(callee_fun, callee_args);
  } else {
    ir.CreateStore(
      ir.CreateCall(callee_fun, callee_args),
      mem_ptr_reg
    );
  }
  ir.CreateRet(mem_ptr_reg);

  return sub_fn;
}

// Generate LLVM function which call extern function
llvm::Function *TraceLifter::Impl::GetDefinedFunction(std::string fun_name, std::string callee_fun_name, LLVMFunTypeIdent llvm_fn_ty_id) {

  llvm::Function *callee_fun;
  if (LLVMFunTypeIdent::NULL_FUN_TY == llvm_fn_ty_id) {
    callee_fun = module->getFunction(callee_fun_name);
    if (!callee_fun) {
      printf("[ERROR] No defined function (%s) is pre-referenced.\n", callee_fun_name.c_str());
      abort();
    }
  } else {
    callee_fun = llvm::cast<llvm::Function>(
      module->getOrInsertFunction(callee_fun_name, arch->LiftedFunctionType()).getCallee()
    );
    callee_fun->setLinkage(llvm::GlobalVariable::ExternalLinkage);
  }
  
  return callee_fun;
}

// Convert LLVMFunTypeIdent to llvm::FunctionType
llvm::FunctionType *TraceLifter::Impl::FunTypeID_2_FunType(LLVMFunTypeIdent llvm_fn_ty_id) {
  
  llvm::FunctionType *fun_type = nullptr;
  switch (llvm_fn_ty_id)
  {
  case LLVMFunTypeIdent::VOID_VOID:
    fun_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {},
      false
    );
    break;
  default:
    printf("[ERROR] The arg of TraceLifter::Impl::FunType_2_FunType must not be LLVMFunTypeIdent::NULL.\n");
    abort();
    break;
  }

  return fun_type;
}

llvm::GlobalVariable *TraceLifter::Impl::SetDataSections(std::vector<BinaryLoader::ELFSection> &sections) {

  std::vector<llvm::Constant*> data_sec_name_ptr_array, data_sec_vma_array, data_sec_size_array, data_sec_bytes_ptr_array;
  uint64_t data_sec_num = 0;

  for (auto &section : sections) {
    if (BinaryLoader::ELFSection::SEC_TYPE_CODE == section.sec_type || BinaryLoader::ELFSection::SEC_TYPE_UNKNOWN == section.sec_type) {
      continue;
    }
    // add global data section "sec_name"
    auto sec_name_val = llvm::ConstantDataArray::getString(context, section.sec_name, true);
    auto __sec_name = new llvm::GlobalVariable(
      *module,
      sec_name_val->getType(),
      true,
      llvm::GlobalVariable::ExternalLinkage,
      sec_name_val,
      "__private_" + section.sec_name + "_sec_name"
    );
    __sec_name->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
    __sec_name->setAlignment(llvm::Align(1));
    data_sec_name_ptr_array.emplace_back(llvm::ConstantExpr::getBitCast(__sec_name, llvm::Type::getInt8PtrTy(context)));
    // gen data section "vma"
    data_sec_vma_array.emplace_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), section.vma));
    // gen data section "size"
    data_sec_size_array.emplace_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), section.size));
    // add global data section "bytes"
    auto sec_bytes_val = llvm::ConstantDataArray::get(context, llvm::ArrayRef<uint8_t>(section.bytes, section.size));
    auto __sec_bytes = new llvm::GlobalVariable(
      *module,
      sec_bytes_val->getType(),
      false,
      llvm::GlobalVariable::ExternalLinkage,
      sec_bytes_val,
      "__private_" + section.sec_name + "_bytes"
    );
    __sec_bytes->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
    __sec_bytes->setAlignment(llvm::Align(1));
    data_sec_bytes_ptr_array.emplace_back(llvm::ConstantExpr::getBitCast(__sec_bytes, llvm::Type::getInt8PtrTy(context)));
    data_sec_num++;
  }

  // add data section nums
  new llvm::GlobalVariable(
    *module,
    llvm::Type::getInt64Ty(context),
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), data_sec_num),
    data_sec_num_name
  );

  auto array_sec_name_ptr_type = llvm::ArrayType::get(llvm::Type::getInt8PtrTy(context), data_sec_name_ptr_array.size());
  auto array_sec_vma_type = llvm::ArrayType::get(llvm::Type::getInt64Ty(context), data_sec_vma_array.size());
  auto array_sec_size_type = llvm::ArrayType::get(llvm::Type::getInt64Ty(context), data_sec_size_array.size());
  auto array_sec_bytes_ptr_type = llvm::ArrayType::get(llvm::Type::getInt8PtrTy(context), data_sec_bytes_ptr_array.size());
  
  // add section "name" ptr array
  auto g_data_sec_name_array = new llvm::GlobalVariable(
    *module,
    array_sec_name_ptr_type,
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(array_sec_name_ptr_type, data_sec_name_ptr_array),
    data_sec_name_array_name 
  );
  // add section "vma" array
  new llvm::GlobalVariable(
    *module,
    array_sec_vma_type,
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(array_sec_vma_type, data_sec_vma_array),
    data_sec_vma_array_name 
  );
  // add section "size" array
  new llvm::GlobalVariable(
    *module,
    array_sec_size_type,
    false,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(array_sec_size_type, data_sec_size_array),
    data_sec_size_array_name 
  );
  // add section "bytes" ptr array
  new llvm::GlobalVariable(
    *module,
    array_sec_bytes_ptr_type,
    false,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(array_sec_bytes_ptr_type, data_sec_bytes_ptr_array),
    data_sec_bytes_array_name 
  );

  return g_data_sec_name_array;
}

llvm::GlobalVariable *TraceLifter::Impl::SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph) {
  
  /* Define e_phent */
  new llvm::GlobalVariable(
    *module,
    llvm::Type::getInt64Ty(context),
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), e_phent),
    e_phent_name
  );
  /* Define e_phnum */
  new llvm::GlobalVariable(
    *module,
    llvm::Type::getInt64Ty(context),
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), e_phnum),
    e_phnum_name
  );
  /* Define e_ph */
  auto e_phdrs_size = e_phent * e_phnum;
  auto e_ph_constants = llvm::ConstantDataArray::get(context, llvm::ArrayRef<uint8_t>(e_ph, e_phdrs_size));
  auto g_e_ph = new llvm::GlobalVariable(
    *module,
    e_ph_constants->getType(),
    false,
    llvm::GlobalVariable::ExternalLinkage,
    e_ph_constants,
    e_ph_name
  );
  g_e_ph->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
  g_e_ph->setAlignment(llvm::Align(1));

  return g_e_ph;
}

llvm::GlobalVariable *TraceLifter::Impl::SetPlatform(const char *platform_name) {
  auto platform_name_val = llvm::ConstantDataArray::getString(context, platform_name, true);
  return new llvm::GlobalVariable(
    *module,
    platform_name_val->getType(),
    true,
    llvm::GlobalVariable::ExternalLinkage,
    platform_name_val,
    g_platform_name
  );
}

/* Set lifted function pointer table */
llvm::GlobalVariable *TraceLifter::Impl::SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  
  std::vector<llvm::Constant*> addr_list, fn_ptr_list;

  for (auto& [addr, fn_name] : addr_fn_map) {
    auto lifted_fun = module->getFunction(fn_name);
    if (!lifted_fun) {
      printf("[ERROR] lifted fun \"%s\" cannot be found.\n", fn_name);
      abort();
    }
    addr_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), addr));
    fn_ptr_list.push_back(lifted_fun);
  }
  /* insert guard */
  addr_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0));
  /* define global fn ptr table */
  auto addr_list_type = llvm::ArrayType::get(llvm::Type::getInt64Ty(context), addr_list.size());
  auto fn_ptr_list_type = llvm::ArrayType::get(fn_ptr_list[0]->getType(), fn_ptr_list.size());
  new llvm::GlobalVariable(
    *module,
    addr_list_type,
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(addr_list_type, addr_list),
    g_addr_list_name
  );
  return new llvm::GlobalVariable(
    *module,
    fn_ptr_list_type,
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(fn_ptr_list_type, fn_ptr_list),
    g_fun_ptr_table_name
  );
}

/* Set control flow debug list */
void TraceLifter::Impl::SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &__control_flow_debug_list) {
  control_flow_debug_list = __control_flow_debug_list;
}

llvm::Function *TraceLifter::Impl::DeclareDebugStateMachine() {
  return llvm::Function::Create(
    llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {},
      false
    ),
    llvm::Function::ExternalLinkage,
    debug_state_machine_name,
    *module
  );
}

llvm::Function *TraceLifter::Impl::DeclareDebugPC() {
  return llvm::Function::Create(
    llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {},
      false
    ),
    llvm::Function::ExternalLinkage,
    debug_pc_name,
    *module
  );
}

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

// Set entry function pointer
void TraceLifter::SetEntryPoint(std::string &entry_func_name) {
  impl->SetEntryPoint(entry_func_name);
}

// Set entry pc
void TraceLifter::SetEntryPC(uint64_t pc) {
  impl->SetEntryPC(pc);
}

// Define pre-referenced function
void TraceLifter::DefinePreReferedFunction(std::string sub_func_name, std::string lifted_func_name, LLVMFunTypeIdent llvm_fn_ty_id) {
  impl->DefinePreReferedFunction(sub_func_name, lifted_func_name, llvm_fn_ty_id);
}

// Set every data sections of the original ELF to LLVM bitcode
void TraceLifter::SetDataSections(std::vector<BinaryLoader::ELFSection> &sections) {
  impl->SetDataSections(sections);
}

/* Set ELF program header info */
void TraceLifter::SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph) {
  impl->SetELFPhdr(e_phent, e_phnum, e_ph);
}

/* Set Platform name */
void TraceLifter::SetPlatform(const char* platform_name) {
  impl->SetPlatform(platform_name);
}

/* Set lifted function pointer table */
void TraceLifter::SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  impl->SetLiftedFunPtrTable(addr_fn_map);
}

/* Set Control Flow debug list */
void TraceLifter::SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &__control_flow_debug_list) {
  impl->SetControlFlowDebugList(__control_flow_debug_list);
}

// Declare debug_state_machine function
void TraceLifter::DeclareDebugStateMachine() {
  impl->DeclareDebugStateMachine();
}

/* Declare debug_pc function */
void TraceLifter::DeclareDebugPC() {
  impl->DeclareDebugPC();
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
  inst.Reset();
  delayed_inst.Reset();

  // Get a trace head that the manager knows about, or that we
  // will eventually tell the trace manager about.
  auto get_trace_decl = [=](uint64_t trace_addr) -> llvm::Function * {
    if (auto lifted_fn = GetLiftedTraceDeclaration(trace_addr)) {
      return lifted_fn;
    } else if (trace_work_list.count(trace_addr)) {
      auto sub_fn_name = manager.TraceName(trace_addr);
      llvm::Function* sub_fn;
      sub_fn = module->getFunction(sub_fn_name);
      // append function declaration
      if (!sub_fn) {
        sub_fn = arch->DeclareLiftedFunction(sub_fn_name, module);
      }
      return sub_fn;
    } else {
      return nullptr;
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

    DLOG(INFO) << "Lifting trace at address " << std::hex << trace_addr
               << std::dec;

    func = get_trace_decl(trace_addr);
    blocks.clear();


    if (!func || !func->isDeclaration()) {
      func = arch->DeclareLiftedFunction(manager.TraceName(trace_addr), module);
    }

    CHECK(func->isDeclaration());


    // Fill in the function, and make sure the block with all register
    // variables jumps to the block that will contain the first instruction
    // of the trace.
    arch->InitializeEmptyLiftedFunction(func);

    auto state_ptr = NthArgument(func, kStatePointerArgNum);

    if (auto entry_block = &(func->front())) {
      auto pc = LoadProgramCounterArg(func);
      auto [next_pc_ref, next_pc_ref_type] =
          this->arch->DefaultLifter(*this->intrinsics)
              ->LoadRegAddress(entry_block, state_ptr, kNextPCVariableName);

      // Initialize `NEXT_PC`.
      (void) new llvm::StoreInst(pc, next_pc_ref, entry_block);

      // Branch to the first basic block.
      llvm::BranchInst::Create(GetOrCreateBlock(trace_addr), entry_block);
    }

    CHECK(inst_work_list.empty());
    inst_work_list.insert(trace_addr);

    // if (0x0041ce80 == trace_addr) {
    //   printf("%lx entry!\n", trace_addr);
    // }

    // Decode instructions. 
    while (!inst_work_list.empty()) {
      const auto inst_addr = PopInstructionAddress();

      block = GetOrCreateBlock(inst_addr);
      switch_inst = nullptr;

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
#if defined(LIFT_DEBUG)
      /* append debug pc function */
      if (control_flow_debug_list.contains(trace_addr) && control_flow_debug_list[trace_addr]) {
        llvm::IRBuilder<> __builder(block);
        auto _debug_pc_fn = module->getFunction(debug_pc_name);
        if (!_debug_pc_fn) {
          printf("[ERROR] debug_pc is undeclared.\n");
          abort();
        }
        printf("0x%llx\n", trace_addr);
        __builder.CreateCall(_debug_pc_fn);
      }
#endif
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

        case Instruction::kCategoryIndirectJump: {
          try_add_delay_slot(true, block);
          AddTerminatingTailCall(block, intrinsics->jump, *intrinsics);
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

          const auto ret_pc_ref = LoadReturnProgramCounterRef(block);
          const auto next_pc_ref = LoadNextProgramCounterRef(block);
          llvm::IRBuilder<> ir(block);
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
