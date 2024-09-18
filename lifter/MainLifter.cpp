#include "MainLifter.h"

#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <utils/Util.h>

// Set RuntimeManager class to the global context
void MainLifter::SetRuntimeManagerClass() {
  static_cast<WrapImpl *>(impl.get())->SetRuntimeManagerClass();
}

/* Set entry function pointer */
void MainLifter::SetEntryPoint(std::string &entry_func_name) {
  static_cast<WrapImpl *>(impl.get())->SetEntryPoint(entry_func_name);
}

/* Set entry pc */
void MainLifter::SetEntryPC(uint64_t pc) {
  static_cast<WrapImpl *>(impl.get())->SetEntryPC(pc);
}

/* Set every data sections of the original ELF to LLVM bitcode */
void MainLifter::SetDataSections(std::vector<BinaryLoader::ELFSection> &sections) {
  static_cast<WrapImpl *>(impl.get())->SetDataSections(sections);
}

/* Set ELF program header info */
void MainLifter::SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph) {
  static_cast<WrapImpl *>(impl.get())->SetELFPhdr(e_phent, e_phnum, e_ph);
}

/* Set Platform name */
void MainLifter::SetPlatform(const char *platform_name) {
  static_cast<WrapImpl *>(impl.get())->SetPlatform(platform_name);
}

/* Set lifted function pointer table */
void MainLifter::SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  static_cast<WrapImpl *>(impl.get())->SetLiftedFunPtrTable(addr_fn_map);
}

/* Set block address data */
void MainLifter::SetBlockAddressData(std::vector<llvm::Constant *> &block_address_ptrs_array,
                                     std::vector<llvm::Constant *> &block_address_vmas_array,
                                     std::vector<llvm::Constant *> &block_address_sizes_array,
                                     std::vector<llvm::Constant *> &block_address_fn_vma_array) {
  static_cast<WrapImpl *>(impl.get())
      ->SetBlockAddressData(block_address_ptrs_array, block_address_vmas_array,
                            block_address_sizes_array, block_address_fn_vma_array);
}

/* Declare helper function used in lifted LLVM bitcode */
void MainLifter::DeclareHelperFunction() {
  static_cast<WrapImpl *>(impl.get())->DeclareHelperFunction();
}

// Optimize the generated LLVM IR.
void MainLifter::Optimize() {
  static_cast<WrapImpl *>(impl.get())->Optimize();
}

/* Set Control Flow debug list */
void MainLifter::SetControlFlowDebugList(std::set<uint64_t> &__control_flow_debug_fnvma_set) {
  static_cast<WrapImpl *>(impl.get())->SetControlFlowDebugList(__control_flow_debug_fnvma_set);
}

/* Declare debug function */
void MainLifter::DeclareDebugFunction() {
  static_cast<WrapImpl *>(impl.get())->DeclareDebugFunction();
}

/* Set lifted function symbol name table */
void MainLifter::SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_map) {
  static_cast<WrapImpl *>(impl.get())->SetFuncSymbolNameTable(addr_fn_map);
}

void MainLifter::SetRegisterNames() {
  static_cast<WrapImpl *>(impl.get())->SetRegisterNames();
}

void MainLifter::WrapImpl::SetRuntimeManagerClass() {
  llvm::StructType::create(context, runtime_manager_name);
}

/* Set entry function pointer */
llvm::GlobalVariable *MainLifter::WrapImpl::SetEntryPoint(std::string &entry_func_name) {

  auto entry_func = module->getFunction(entry_func_name);
  /* no defined entry function */
  if (!entry_func) {
    // elfconv_runtime_error("[ERROR] Entry function is not defined. expected: %s\n",
    //                       entry_func_name.c_str());
    auto bg = module->getFunctionList().begin();
    for (; bg != module->getFunctionList().end();) {
      auto strr = bg->getName().str();
      if (strr.find("_start") != std::string::npos)
        printf("%s\n", strr.c_str());
      bg++;
    }
    return nullptr;
  }
  auto g_entry_func = new llvm::GlobalVariable(*module, entry_func->getType(), true,
                                               llvm::GlobalVariable::ExternalLinkage, entry_func,
                                               g_entry_func_name);
  g_entry_func->setAlignment(llvm::MaybeAlign(8));

  return g_entry_func;
}

/* Set entry pc */
llvm::GlobalVariable *MainLifter::WrapImpl::SetEntryPC(uint64_t pc) {

  auto ty = llvm::Type::getInt64Ty(context);
  auto entry_pc = new llvm::GlobalVariable(*module, ty, true, llvm::GlobalVariable::ExternalLinkage,
                                           llvm::ConstantInt::get(ty, pc), g_entry_pc_name);
  entry_pc->setAlignment(llvm::MaybeAlign(8));

  return entry_pc;
}

llvm::GlobalVariable *
MainLifter::WrapImpl::SetDataSections(std::vector<BinaryLoader::ELFSection> &sections) {

  std::vector<llvm::Constant *> data_sec_name_ptr_array, data_sec_vma_array, data_sec_size_array,
      data_sec_bytes_ptr_array;
  uint64_t data_sec_num = 0;

  for (auto &section : sections) {
    if (BinaryLoader::ELFSection::SEC_TYPE_CODE == section.sec_type ||
        BinaryLoader::ELFSection::SEC_TYPE_UNKNOWN == section.sec_type) {
      continue;
    }
    // add global data section "sec_name"
    auto sec_name_val = llvm::ConstantDataArray::getString(context, section.sec_name, true);
    auto __sec_name = new llvm::GlobalVariable(*module, sec_name_val->getType(), true,
                                               llvm::GlobalVariable::ExternalLinkage, sec_name_val,
                                               "__private_" + section.sec_name + "_sec_name");
    __sec_name->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
    __sec_name->setAlignment(llvm::Align(1));
    data_sec_name_ptr_array.emplace_back(
        llvm::ConstantExpr::getBitCast(__sec_name, llvm::Type::getInt8PtrTy(context)));
    // gen data section "vma"
    data_sec_vma_array.emplace_back(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), section.vma));
    // gen data section "size"
    data_sec_size_array.emplace_back(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), section.size));
    // add global data section "bytes"
    auto sec_bytes_val =
        llvm::ConstantDataArray::get(context, llvm::ArrayRef<uint8_t>(section.bytes, section.size));
    auto __sec_bytes = new llvm::GlobalVariable(
        *module, sec_bytes_val->getType(), false, llvm::GlobalVariable::ExternalLinkage,
        sec_bytes_val, "__private_" + section.sec_name + "_bytes");
    __sec_bytes->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
    __sec_bytes->setAlignment(llvm::Align(1));
    data_sec_bytes_ptr_array.emplace_back(
        llvm::ConstantExpr::getBitCast(__sec_bytes, llvm::Type::getInt8PtrTy(context)));
    data_sec_num++;
  }

  // add data section nums
  new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalVariable::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), data_sec_num), data_sec_num_name);

  /* generate global array */
  GenGlobalArrayHelper(llvm::Type::getInt8PtrTy(context), data_sec_name_ptr_array,
                       data_sec_name_array_name);
  GenGlobalArrayHelper(llvm::Type::getInt64Ty(context), data_sec_vma_array,
                       data_sec_vma_array_name);
  GenGlobalArrayHelper(llvm::Type::getInt64Ty(context), data_sec_size_array,
                       data_sec_size_array_name);
  return GenGlobalArrayHelper(llvm::Type::getInt8PtrTy(context), data_sec_bytes_ptr_array,
                              data_sec_bytes_array_name);
}

llvm::GlobalVariable *MainLifter::WrapImpl::SetELFPhdr(uint64_t e_phent, uint64_t e_phnum,
                                                       uint8_t *e_ph) {

  /* Define e_phent */
  new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalVariable::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), e_phent), e_phent_name);
  /* Define e_phnum */
  new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalVariable::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), e_phnum), e_phnum_name);
  /* Define e_ph */
  auto e_phdrs_size = e_phent * e_phnum;
  auto e_ph_constants =
      llvm::ConstantDataArray::get(context, llvm::ArrayRef<uint8_t>(e_ph, e_phdrs_size));
  auto g_e_ph =
      new llvm::GlobalVariable(*module, e_ph_constants->getType(), false,
                               llvm::GlobalVariable::ExternalLinkage, e_ph_constants, e_ph_name);
  g_e_ph->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
  g_e_ph->setAlignment(llvm::Align(1));

  return g_e_ph;
}

llvm::GlobalVariable *MainLifter::WrapImpl::SetPlatform(const char *platform_name) {
  auto platform_name_val = llvm::ConstantDataArray::getString(context, platform_name, true);
  return new llvm::GlobalVariable(*module, platform_name_val->getType(), true,
                                  llvm::GlobalVariable::ExternalLinkage, platform_name_val,
                                  g_platform_name);
}

/* Set lifted function pointer table */
llvm::GlobalVariable *MainLifter::WrapImpl::SetLiftedFunPtrTable(
    std::unordered_map<uint64_t, const char *> &addr_fn_map) {

  std::vector<llvm::Constant *> addr_list, fn_ptr_list;

  for (auto &[addr, fn_name] : addr_fn_map) {
    auto lifted_fun = module->getFunction(fn_name);
    if (!lifted_fun) {
      elfconv_runtime_error("[ERROR] lifted fun \"%s\" cannot be found.\n", fn_name);
    }
    addr_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), addr));
    fn_ptr_list.push_back(lifted_fun);
  }
  /* insert guard */
  addr_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0));
  /* define global fn ptr table */
  GenGlobalArrayHelper(llvm::Type::getInt64Ty(context), addr_list, g_addr_list_name);
  return GenGlobalArrayHelper(fn_ptr_list[0]->getType(), fn_ptr_list, g_fun_ptr_table_name);
}

/* Set block address data */
llvm::GlobalVariable *MainLifter::WrapImpl::SetBlockAddressData(
    std::vector<llvm::Constant *> &block_address_ptrs_array,
    std::vector<llvm::Constant *> &block_address_vmas_array,
    std::vector<llvm::Constant *> &block_address_sizes_array,
    std::vector<llvm::Constant *> &block_address_fn_vma_array) {
  (void) new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalValue::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), block_address_ptrs_array.size()),
      g_block_address_array_size_name);
  GenGlobalArrayHelper(llvm::Type::getInt64PtrTy(context), block_address_ptrs_array,
                       g_block_address_ptrs_array_name);
  GenGlobalArrayHelper(llvm::Type::getInt64PtrTy(context), block_address_vmas_array,
                       g_block_address_vmas_array_name);
  GenGlobalArrayHelper(llvm::Type::getInt64Ty(context), block_address_sizes_array,
                       g_block_address_size_array_name);
  return GenGlobalArrayHelper(llvm::Type::getInt64Ty(context), block_address_fn_vma_array,
                              g_block_address_fn_vma_array_name);
}

/* Global variable array definition helper */
llvm::GlobalVariable *MainLifter::WrapImpl::GenGlobalArrayHelper(
    llvm::Type *elem_type, std::vector<llvm::Constant *> &constant_array, const llvm::Twine &Name,
    bool isConstant, llvm::GlobalValue::LinkageTypes linkage) {
  auto constant_array_type = llvm::ArrayType::get(elem_type, constant_array.size());
  return new llvm::GlobalVariable(*module, constant_array_type, isConstant, linkage,
                                  llvm::ConstantArray::get(constant_array_type, constant_array),
                                  Name);
}

/* declare helper function in the lifted LLVM bitcode */
void MainLifter::WrapImpl::DeclareHelperFunction() {
  /* uint64_t *__g_get_jmp_block_address(RuntimeManager*,  uint64_t, uint64_t) */
  llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getInt64PtrTy(context),
                              {llvm::Type::getInt64PtrTy(context), llvm::Type::getInt64Ty(context),
                               llvm::Type::getInt64Ty(context)},
                              false),
      llvm::Function::ExternalLinkage, g_get_indirectbr_block_address_func_name, *module);
}

/* Prepare the virtual machine for instruction test */
llvm::BasicBlock *MainLifter::WrapImpl::PreVirtualMachineForInsnTest(uint64_t, TraceManager &,
                                                                     llvm::BranchInst *) {
  elfconv_runtime_error("%s must be called by derived class.\n", __func__);
}

/* Check the virtual machine for instruction test */
llvm::BranchInst *MainLifter::WrapImpl::CheckVirtualMahcineForInsnTest(uint64_t, TraceManager &) {
  elfconv_runtime_error("%s must be called by derived class.\n", __func__);
}

void MainLifter::WrapImpl::AddTestFailedBlock() {
  elfconv_runtime_error("%s must be called by derived class.\n", __func__);
}

/* Set control flow debug list */
void MainLifter::WrapImpl::SetControlFlowDebugList(
    std::set<uint64_t> &__control_flow_debug_fnvma_set) {
  control_flow_debug_fnvma_set = __control_flow_debug_fnvma_set;
}

/* Declare debug function */
llvm::Function *MainLifter::WrapImpl::DeclareDebugFunction() {

  auto runtime_manager_ptr_type = llvm::Type::getInt64PtrTy(context);
  auto void_ty = llvm::Type::getVoidTy(context);
  auto u64_ty = llvm::Type::getInt64Ty(context);
  auto f64_ty = llvm::Type::getDoubleTy(context);
  auto u8p_ty = llvm::Type::getInt8PtrTy(context);
  auto extern_link = llvm::Function::ExternalLinkage;

  /* void debug_state_machine() */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {}, false), extern_link,
                         debug_state_machine_name, *module);
  /* void debug_state_machine_vectors() */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {}, false), extern_link,
                         debug_state_machine_vectors_name, *module);
  /* void debug_llvmir_u64value(uint64_t val) */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {u64_ty}, false), extern_link,
                         debug_llvmir_u64value_name, *module);
  /* void debug_llvmir_f64vaule(double val) */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {f64_ty}, false), extern_link,
                         debug_llvmir_f64value_name, *module);
  /* void debug_call_stack_push() */
  llvm::Function::Create(
      llvm::FunctionType::get(void_ty, {runtime_manager_ptr_type, u64_ty}, false), extern_link,
      debug_call_stack_push_name, *module);
  /* void debug_call_stack_pop() */
  llvm::Function::Create(
      llvm::FunctionType::get(void_ty, {runtime_manager_ptr_type, u64_ty}, false), extern_link,
      debug_call_stack_pop_name, *module);
  // void debug_memory_value_change()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {runtime_manager_ptr_type}, false),
                         extern_link, debug_memory_value_change_name, *module);
  // void debug_memory_value()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {runtime_manager_ptr_type}, false),
                         extern_link, debug_memory_value_name, *module);
  // temporary patch fun
  llvm::Function::Create(
      llvm::FunctionType::get(void_ty, {runtime_manager_ptr_type, u64_ty}, false), extern_link,
      "temp_patch_f_flags", *module);
  /* void debug_insn() */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {}, false), extern_link, debug_insn_name,
                         *module);
  // void debug_reach()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {}, false), extern_link, debug_reach_name,
                         *module);
  // void debug_string()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {u8p_ty}, false), extern_link,
                         debug_string_name, *module);
  // void debug_vma_and_registers()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {u64_ty, u64_ty}, true), extern_link,
                         debug_vma_and_registers_name, *module);
  return nullptr;
}

void MainLifter::WrapImpl::SetRegisterNames() {
  std::string x_reg_name = "X";
  std::string v_reg_name = "V";
  for (size_t i = 0; i < 31; i++) {
    // X register
    // e.g. debug_X5 = "X5"
    auto x_reg_name_i = x_reg_name + to_string(i);
    auto x_reg_name_i_val = llvm::ConstantDataArray::getString(context, x_reg_name_i, true);
    new llvm::GlobalVariable(*module, x_reg_name_i_val->getType(), true,
                             llvm::GlobalVariable::ExternalLinkage, x_reg_name_i_val,
                             "debug_" + x_reg_name_i);
    // V register
    // e.g. debug_V5 = "V5"
    auto v_reg_name_i = v_reg_name + to_string(i);
    auto v_reg_name_i_val = llvm::ConstantDataArray::getString(context, v_reg_name_i, true);
    new llvm::GlobalVariable(*module, v_reg_name_i_val->getType(), true,
                             llvm::GlobalVariable::ExternalLinkage, v_reg_name_i_val,
                             "debug_" + v_reg_name_i);
  }

  auto ecv_nzcv_name_val = llvm::ConstantDataArray::getString(context, "ECV_NZCV", true);
  new llvm::GlobalVariable(*module, ecv_nzcv_name_val->getType(), true,
                           llvm::GlobalVariable::ExternalLinkage, ecv_nzcv_name_val,
                           "debug_ECV_NZCV");
}

/* Set lifted function symbol name table */
llvm::GlobalVariable *MainLifter::WrapImpl::SetFuncSymbolNameTable(
    std::unordered_map<uint64_t, const char *> &addr_fn_map) {

  std::vector<llvm::Constant *> func_symbol_ptr_list, fn_vma_list;

  for (auto &[fn_addr, symbol_name] : addr_fn_map) {
    auto symbol_name_val = llvm::ConstantDataArray::getString(context, symbol_name, true);
    auto symbol_name_gvar = new llvm::GlobalVariable(*module, symbol_name_val->getType(), true,
                                                     llvm::GlobalVariable::ExternalLinkage,
                                                     symbol_name_val, symbol_name);
    symbol_name_gvar->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
    symbol_name_gvar->setAlignment(llvm::Align(1));
    func_symbol_ptr_list.emplace_back(
        llvm::ConstantExpr::getBitCast(symbol_name_gvar, llvm::Type::getInt8PtrTy(context)));
    fn_vma_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), fn_addr));
  }

  GenGlobalArrayHelper(llvm::Type::getInt8PtrTy(context), func_symbol_ptr_list,
                       g_fun_symbol_table_name);
  return GenGlobalArrayHelper(llvm::Type::getInt64Ty(context), fn_vma_list,
                              g_addr_list_second_name);
}
