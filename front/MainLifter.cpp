#include "remill/BC/ABI.h"
#include "remill/Arch/Arch.h"

#include "MainLifter.h"

/* Set entry function pointer */
void MainLifter::SetEntryPoint(std::string &entry_func_name) {
  static_cast<WrapImpl*>(impl.get())->SetEntryPoint(entry_func_name);
}

/* Set entry pc */
void MainLifter::SetEntryPC(uint64_t pc) {
  static_cast<WrapImpl*>(impl.get())->SetEntryPC(pc);
}

/* Define pre-referenced function */
void MainLifter::DefinePreReferedFunction(std::string sub_func_name, std::string lifted_func_name, LLVMFunTypeIdent llvm_fn_ty_id) {
  static_cast<WrapImpl*>(impl.get())->DefinePreReferedFunction(sub_func_name, lifted_func_name, llvm_fn_ty_id);
}

/* Set every data sections of the original ELF to LLVM bitcode */
void MainLifter::SetDataSections(std::vector<BinaryLoader::ELFSection> &sections) {
  static_cast<WrapImpl*>(impl.get())->SetDataSections(sections);
}

/* Set ELF program header info */
void MainLifter::SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph) {
  static_cast<WrapImpl*>(impl.get())->SetELFPhdr(e_phent, e_phnum, e_ph);
}

/* Set Platform name */
void MainLifter::SetPlatform(const char* platform_name) {
  static_cast<WrapImpl*>(impl.get())->SetPlatform(platform_name);
}

/* Set lifted function pointer table */
void MainLifter::SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  static_cast<WrapImpl*>(impl.get())->SetLiftedFunPtrTable(addr_fn_map);
}

/* Set Control Flow debug list */
void MainLifter::SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &__control_flow_debug_list) {
  static_cast<WrapImpl*>(impl.get())->SetControlFlowDebugList(__control_flow_debug_list);
}

/* Declare debug function */
void MainLifter::DeclareDebugFunction() {
  static_cast<WrapImpl*>(impl.get())->DeclareDebugFunction();
}

/* Set lifted function symbol name table */
void MainLifter::SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  static_cast<WrapImpl*>(impl.get())->SetFuncSymbolNameTable(addr_fn_map);
}

/* Set entry function pointer */ 
llvm::GlobalVariable *MainLifter::WrapImpl::SetEntryPoint(std::string &entry_func_name) {
    
  auto entry_func = module->getFunction(entry_func_name);
  /* no defined entry function */
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

/* Set entry pc */
llvm::GlobalVariable *MainLifter::WrapImpl::SetEntryPC(uint64_t pc) {
  
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

/* Define pre-referenced function */
llvm::Function *MainLifter::WrapImpl::DefinePreReferedFunction(std::string fun_name, std::string callee_fun_name, LLVMFunTypeIdent llvm_fn_ty_id) {
  
  auto callee_fun = GetDefinedFunction(fun_name, callee_fun_name, llvm_fn_ty_id);

  /* generate sub function */
  llvm::Function *sub_fn;
  sub_fn = module->getFunction(fun_name);
  if (!sub_fn) {
    sub_fn = arch->DeclareLiftedFunction(fun_name, module);
  }
  /* insert callee basic block */
  auto *callee_bb = llvm::BasicBlock::Create(context, "entry", sub_fn);
  llvm::IRBuilder<> ir(callee_bb);
  std::vector<llvm::Value*> callee_args;
  for (size_t _arg_i = 0;_arg_i < sub_fn->arg_size();_arg_i++) {
    callee_args.emplace_back(sub_fn->getArg(_arg_i));
  }
  llvm::AllocaInst *mem_ptr_reg = ir.CreateAlloca(word_type, nullptr, kMemoryVariableName);
  mem_ptr_reg->setAlignment(llvm::Align(8));
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

/* Generate LLVM function which call extern function */
llvm::Function *MainLifter::WrapImpl::GetDefinedFunction(std::string fun_name, std::string callee_fun_name, LLVMFunTypeIdent llvm_fn_ty_id) {

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

/* Convert LLVMFunTypeIdent to llvm::FunctionType */
llvm::FunctionType *MainLifter::WrapImpl::FunTypeID_2_FunType(LLVMFunTypeIdent llvm_fn_ty_id) {
  
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
    printf("[ERROR] The arg of MainLifter::WrapImpl::FunType_2_FunType must not be LLVMFunTypeIdent::NULL.\n");
    abort();
    break;
  }

  return fun_type;
}

llvm::GlobalVariable *MainLifter::WrapImpl::SetDataSections(std::vector<BinaryLoader::ELFSection> &sections) {

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

llvm::GlobalVariable *MainLifter::WrapImpl::SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph) {
  
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

llvm::GlobalVariable *MainLifter::WrapImpl::SetPlatform(const char *platform_name) {
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
llvm::GlobalVariable *MainLifter::WrapImpl::SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  
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
void MainLifter::WrapImpl::SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &__control_flow_debug_list) {
  control_flow_debug_list = __control_flow_debug_list;
}

/* Declare debug function */
llvm::Function *MainLifter::WrapImpl::DeclareDebugFunction() {
  /* void debug_state_machine() */
  llvm::Function::Create(
    llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {},
      false
    ),
    llvm::Function::ExternalLinkage,
    debug_state_machine_name,
    *module
  );
  /* void debug_call_stack() */
  llvm::Function::Create(
    llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {},
      false
    ),
    llvm::Function::ExternalLinkage,
    debug_pc_name,
    *module
  );
  /* void debug_call_stack() */
  return llvm::Function::Create(
    llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {},
      false
    ),
    llvm::Function::ExternalLinkage,
    debug_call_stack_name,
    *module
  );
}

/* Set lifted function symbol name table */
llvm::GlobalVariable *MainLifter::WrapImpl::SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  
  std::vector<llvm::Constant*> func_symbol_ptr_list, fn_vma_list;
  
  for (auto& [fn_addr, symbol_name] : addr_fn_map) {
    auto symbol_name_val = llvm::ConstantDataArray::getString(context, symbol_name, true);
    auto symbol_name_gvar = new llvm::GlobalVariable(
      *module,
      symbol_name_val->getType(),
      true,
      llvm::GlobalVariable::ExternalLinkage,
      symbol_name_val,
      symbol_name
    );
    symbol_name_gvar->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
    symbol_name_gvar->setAlignment(llvm::Align(1));
    func_symbol_ptr_list.emplace_back(llvm::ConstantExpr::getBitCast(symbol_name_gvar, llvm::Type::getInt8PtrTy(context)));
    fn_vma_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), fn_addr));
  }

  auto array_symbol_name_ptr_type = llvm::ArrayType::get(llvm::Type::getInt8PtrTy(context), func_symbol_ptr_list.size());
  auto array_fn_vma_type = llvm::ArrayType::get(llvm::Type::getInt64Ty(context), fn_vma_list.size());
  
  auto array_symbol_name_ptrs = new llvm::GlobalVariable(
    *module,
    array_symbol_name_ptr_type,
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(array_symbol_name_ptr_type, func_symbol_ptr_list),
    g_fun_symbol_table_name
  );
  new llvm::GlobalVariable (
    *module,
    array_fn_vma_type,
    true,
    llvm::GlobalVariable::ExternalLinkage,
    llvm::ConstantArray::get(array_fn_vma_type, fn_vma_list),
    g_addr_list_second_name
  );
  
  return array_symbol_name_ptrs;
}