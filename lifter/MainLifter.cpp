#include "MainLifter.h"

#include "lifter/TraceManager.h"
#include "remill/BC/TraceLifter.h"

#include <cstddef>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/HelperMacro.h>
#include <unordered_map>
#include <utils/Util.h>

// Set RuntimeManager class to the global context
void MainLifter::SetRuntimeManagerClass() {
  static_cast<WrapImpl *>(impl.get())->SetRuntimeManagerClass();
}

/* Set entry function pointer */
void MainLifter::SetEntryPoint(std::string &entry_func_name) {
  CHECK(!entry_func_name.empty());
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
void MainLifter::SetLiftedFunPtrTable(
    std::unordered_map<uint64_t, const char *> &addr_fn_name_map) {
  static_cast<WrapImpl *>(impl.get())->SetLiftedFunPtrTable(addr_fn_name_map);
}

void MainLifter::SetLiftedNoOptFunPtrTable(
    std::unordered_map<uint64_t, const char *> &addr_noopt_fun_name_map, bool able_vrp_opt) {
  static_cast<WrapImpl *>(impl.get())
      ->SetLiftedNoOptFunPtrTable(addr_noopt_fun_name_map, able_vrp_opt);
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

void MainLifter::SetOptMode(bool able_vrp_opt, bool norm_mode) {
  static_cast<WrapImpl *>(impl.get())->SetOptMode(able_vrp_opt, norm_mode);
}

/* Declare helper function used in lifted LLVM bitcode */
void MainLifter::DeclareHelperFunction() {
  static_cast<WrapImpl *>(impl.get())->DeclareHelperFunction();
}

// Set noopt vma and basic blocks
void MainLifter::SetNoOptVmaBBLists(bool able_vrp_opt) {
  static_cast<WrapImpl *>(impl.get())
      ->SetNoOptVmaBBLists(impl.get()->noopt_all_vma_bbs, able_vrp_opt);
}

// Optimize the generated LLVM IR.
void MainLifter::Optimize() {
  static_cast<WrapImpl *>(impl.get())->Optimize();
}

/* Declare debug function */
void MainLifter::DeclareDebugFunction() {
  static_cast<WrapImpl *>(impl.get())->DeclareDebugFunction();
}

/* Set lifted function symbol name table */
void MainLifter::SetFuncSymbolNameTable(
    std::unordered_map<uint64_t, const char *> &addr_fn_name_map) {
  static_cast<WrapImpl *>(impl.get())->SetFuncSymbolNameTable(addr_fn_name_map);
}

void MainLifter::SetRegisterDebugNames() {
  static_cast<WrapImpl *>(impl.get())->SetRegisterDebugNames();
}

void MainLifter::WrapImpl::SetRuntimeManagerClass() {
  llvm::StructType::create(context, runtime_manager_name);
}

void MainLifter::SetCommonMetaData(LiftConfig lift_config) {
  AArch64TraceManager *target_manager = static_cast<AArch64TraceManager *>(&impl.get()->manager);

  SetRuntimeManagerClass();
  DeclareHelperFunction();
  SetELFPhdr(target_manager->elf_obj.e_phent, target_manager->elf_obj.e_phnum,
             target_manager->elf_obj.e_ph);
  SetEntryPC(target_manager->entry_point);
  SetDataSections(target_manager->elf_obj.sections);
  SetOptMode(target_manager->elf_obj.able_vrp_opt, lift_config.norm_mode);

  if (target_manager->target_arch == "aarch64") {
    SetPlatform("aarch64");
  } else if (target_manager->target_arch == "x86_64") {
    SetPlatform("x86_64");
  }

  // Debug.
  DeclareDebugFunction();
  SetRegisterDebugNames();
}

void MainLifter::SubseqOfLifting(
    std::unordered_map<uint64_t, const char *> &addr_opt_fun_name_map) {
  AArch64TraceManager *target_manager = static_cast<AArch64TraceManager *>(&impl.get()->manager);
  CHECK(!addr_opt_fun_name_map.empty() && target_manager->elf_obj.able_vrp_opt);

  SetEntryPoint(target_manager->entry_func_lifted_name);
  SetLiftedFunPtrTable(addr_opt_fun_name_map);
  Optimize();

  // `_ecv_noopt_func_entrys` and `_ecv_noopt_fun_ptrs` must be declared
  // because they are used in the Entry process.
  // std::unordered_map<uint64_t, const char *> dummy_map;
  // SetLiftedNoOptFunPtrTable(dummy_map, false);

  SetBlockAddressData(
      target_manager->g_block_address_ptrs_array, target_manager->g_block_address_vmas_array,
      target_manager->g_block_address_size_array, target_manager->g_block_address_fn_vma_array);
}

void MainLifter::SubseqForNoOptLifting(
    std::unordered_map<uint64_t, const char *> &addr_noopt_fun_name_map) {
  AArch64TraceManager *target_manager = static_cast<AArch64TraceManager *>(&impl.get()->manager);
  CHECK(!addr_noopt_fun_name_map.empty() && !target_manager->elf_obj.able_vrp_opt);

  SetEntryPoint(target_manager->entry_func_lifted_name);
  SetLiftedFunPtrTable(addr_noopt_fun_name_map);
  // In the current implementation, we cannot use linear bascic block address array
  // because some instructions may be lifted on multiple times.
  // SetNoOptVmaBBLists(target_manager->elf_obj.able_vrp_opt);

  SetBlockAddressData(
      target_manager->g_block_address_ptrs_array, target_manager->g_block_address_vmas_array,
      target_manager->g_block_address_size_array, target_manager->g_block_address_fn_vma_array);

#if defined(LIFT_CALLSTACK_DEBUG) || defined(LIFT_FUNC_SYMBOLS) || defined(CALLED_FUNC_NAME)
  SetFuncSymbolNameTable(addr_noopt_fun_name_map);
#endif
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
                                               ecv_entry_func_name);
  g_entry_func->setAlignment(llvm::MaybeAlign(8));

  return g_entry_func;
}

/* Set entry pc */
llvm::GlobalVariable *MainLifter::WrapImpl::SetEntryPC(uint64_t pc) {

  auto ty = llvm::Type::getInt64Ty(context);
  auto entry_pc = new llvm::GlobalVariable(*module, ty, true, llvm::GlobalVariable::ExternalLinkage,
                                           llvm::ConstantInt::get(ty, pc), ecv_entry_pc_name);
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
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), data_sec_num), ecv_data_sec_num_name);

  /* generate global array */
  SetGblArrayIr(llvm::Type::getInt8PtrTy(context), data_sec_name_ptr_array,
                ecv_data_sec_name_array_name);
  SetGblArrayIr(llvm::Type::getInt64Ty(context), data_sec_vma_array, ecv_data_sec_vma_array_name);
  SetGblArrayIr(llvm::Type::getInt64Ty(context), data_sec_size_array, ecv_data_sec_size_array_name);
  return SetGblArrayIr(llvm::Type::getInt8PtrTy(context), data_sec_bytes_ptr_array,
                       ecv_data_sec_bytes_array_name);
}

llvm::GlobalVariable *MainLifter::WrapImpl::SetELFPhdr(uint64_t e_phent, uint64_t e_phnum,
                                                       uint8_t *e_ph) {

  /* Define e_phent */
  new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalVariable::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), e_phent), ecv_e_phent_name);
  /* Define e_phnum */
  new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalVariable::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), e_phnum), ecv_e_phnum_name);
  /* Define e_ph */
  auto e_phdrs_size = e_phent * e_phnum;
  auto e_ph_constants =
      llvm::ConstantDataArray::get(context, llvm::ArrayRef<uint8_t>(e_ph, e_phdrs_size));
  auto g_e_ph = new llvm::GlobalVariable(*module, e_ph_constants->getType(), false,
                                         llvm::GlobalVariable::ExternalLinkage, e_ph_constants,
                                         ecv_e_ph_name);
  g_e_ph->setUnnamedAddr(llvm::GlobalVariable::UnnamedAddr::Global);
  g_e_ph->setAlignment(llvm::Align(1));

  return g_e_ph;
}

llvm::GlobalVariable *MainLifter::WrapImpl::SetPlatform(const char *platform_name) {
  auto platform_name_val = llvm::ConstantDataArray::getString(context, platform_name, true);
  return new llvm::GlobalVariable(*module, platform_name_val->getType(), true,
                                  llvm::GlobalVariable::ExternalLinkage, platform_name_val,
                                  ecv_platform_name);
}

/* Set lifted function pointer table */
void MainLifter::WrapImpl::SetLiftedFunPtrTable(
    std::unordered_map<uint64_t, const char *> &addr_fn_name_map) {

  std::vector<llvm::Constant *> addr_list, fn_ptr_list;

  for (auto &[addr, fn_name] : addr_fn_name_map) {
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
  SetGblArrayIr(llvm::Type::getInt64Ty(context), addr_list, "_ecv_fun_vmas");
  SetGblArrayIr(llvm::Type::getInt64PtrTy(context), fn_ptr_list, "_ecv_fun_ptrs");
}

// is not used now.
void MainLifter::WrapImpl::SetLiftedNoOptFunPtrTable(
    std::unordered_map<uint64_t, const char *> &addr_noopt_fun_name_map, bool able_vrp_otp) {

  std::vector<llvm::Constant *> addr_list, fn_ptr_list;

  if (!able_vrp_otp) {
    for (auto &[addr, fun_name] : addr_noopt_fun_name_map) {
      auto lifted_fun = module->getFunction(fun_name);
      if (!lifted_fun) {
        elfconv_runtime_error("[ERROR] lifted fun \"%s\" cannot be found.\n", fun_name);
      }
      addr_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), addr));
      fn_ptr_list.push_back(lifted_fun);
    }
    // Insert guard
    addr_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0));
  }

  // Define global fn ptr table
  SetGblArrayIr(llvm::Type::getInt64Ty(context), addr_list, "_ecv_noopt_func_entrys");
  SetGblArrayIr(llvm::Type::getInt64PtrTy(context), fn_ptr_list, "_ecv_noopt_fun_ptrs");
}

/* Set block address data */
void MainLifter::WrapImpl::SetBlockAddressData(
    std::vector<llvm::Constant *> &block_address_ptrs_array,
    std::vector<llvm::Constant *> &block_address_vmas_array,
    std::vector<llvm::Constant *> &block_address_sizes_array,
    std::vector<llvm::Constant *> &block_address_fn_vma_array) {
  (void) new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalValue::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), block_address_ptrs_array.size()),
      ecv_block_address_array_size_name);
  SetGblArrayIr(llvm::Type::getInt64PtrTy(context), block_address_ptrs_array,
                ecv_block_address_ptrs_array_name);
  SetGblArrayIr(llvm::Type::getInt64PtrTy(context), block_address_vmas_array,
                ecv_block_address_vmas_array_name);
  SetGblArrayIr(llvm::Type::getInt64Ty(context), block_address_sizes_array,
                ecv_block_address_size_array_name);
  SetGblArrayIr(llvm::Type::getInt64Ty(context), block_address_fn_vma_array,
                ecv_block_address_fn_vma_array_name);
}

void MainLifter::WrapImpl::SetOptMode(bool able_vrp_opt, bool __norm_mode) {
  // vrp_opt always be disabled if the norm_mode on.
  if (__norm_mode) {
    norm_mode = true;
    vrp_opt_mode = false;
  } else {
    norm_mode = false;
    vrp_opt_mode = able_vrp_opt;
  }
}

/* Global variable array definition helper */
llvm::GlobalVariable *MainLifter::WrapImpl::SetGblArrayIr(
    llvm::Type *elem_type, std::vector<llvm::Constant *> &constant_array, const llvm::Twine &Name,
    bool isConstant, llvm::GlobalValue::LinkageTypes linkage) {
  auto constant_array_type = llvm::ArrayType::get(elem_type, constant_array.size());
  return new llvm::GlobalVariable(*module, constant_array_type, isConstant, linkage,
                                  llvm::ConstantArray::get(constant_array_type, constant_array),
                                  Name);
}

// is not used now.
void MainLifter::WrapImpl::SetNoOptVmaBBLists(
    std::vector<std::pair<uint64_t, llvm::Constant *>> noopt_all_vma_bbs, bool able_vrp_opt) {

  std::vector<llvm::Constant *> vmas, bb_addrs;

  if (!able_vrp_opt) {
    std::sort(noopt_all_vma_bbs.begin(), noopt_all_vma_bbs.end());
    for (auto &[vma, bb_addr] : noopt_all_vma_bbs) {
      vmas.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), vma));
      bb_addrs.push_back(bb_addr);
    }
  }

  // _ecv_noopt_inst_vmas
  SetGblArrayIr(llvm::Type::getInt64Ty(context), vmas, "_ecv_noopt_inst_vmas");
  // _ecv_noopt_bb_ptrs
  SetGblArrayIr(llvm::Type::getInt64PtrTy(context), bb_addrs, "_ecv_noopt_bb_ptrs");
  // _ecv_noopt_list_size
  new llvm::GlobalVariable(
      *module, llvm::Type::getInt64Ty(context), true, llvm::GlobalValue::ExternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), noopt_all_vma_bbs.size()),
      "_ecv_noopt_vmabbs_size");
}

/* declare helper function in the lifted LLVM bitcode */
void MainLifter::WrapImpl::DeclareHelperFunction() {

  // uint64_t *__g_get_jmp_block_address(RuntimeManager*, uint64_t, uint64_t)
  llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getInt64PtrTy(context),
                              {llvm::Type::getInt64PtrTy(context), llvm::Type::getInt64Ty(context),
                               llvm::Type::getInt64Ty(context)},
                              false),
      llvm::Function::ExternalLinkage, g_get_indirectbr_block_address_func_name, *module);

  // uint64_t *_ecv_noopt_get_bb(RuntimeManager *, addr_t, addr_t)
  llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getInt64PtrTy(context),
                              {llvm::Type::getInt64PtrTy(context), llvm::Type::getInt64Ty(context),
                               llvm::Type::getInt64Ty(context)},
                              false),
      llvm::Function::ExternalLinkage, _ecv_noopt_get_bb_name, *module);

  // void _ecv_process_context_switch(RuntimeManager *);
  llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                                                 {llvm::Type::getInt64PtrTy(context)}, false),
                         llvm::Function::ExternalLinkage, "_ecv_process_context_switch", *module);

  // void _ecv_save_call_history(State &state, RuntimeManager &rt_m, uint64_t, uint64_t);
  llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                              {llvm::Type::getInt64PtrTy(context),
                               llvm::Type::getInt64PtrTy(context), llvm::Type::getInt64Ty(context),
                               llvm::Type::getInt64Ty(context)},
                              false),
      llvm::Function::ExternalLinkage, "_ecv_save_call_history", *module);

  // void _ecv_func_epilogue(State &, addr_t, RuntimeManager &);
  llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                                                 {llvm::Type::getInt64PtrTy(context),
                                                  llvm::Type::getInt64PtrTy(context)},
                                                 false),
                         llvm::Function::ExternalLinkage, "_ecv_func_epilogue", *module);

  // void _ecv_unreached();
  llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                                                 {llvm::Type::getInt64Ty(context)}, false),
                         llvm::Function::ExternalLinkage, "_ecv_unreached", *module);
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

/* Declare debug function */
llvm::Function *MainLifter::WrapImpl::DeclareDebugFunction() {

  auto rt_m_ty = llvm::Type::getInt64PtrTy(context);
  auto void_ty = llvm::Type::getVoidTy(context);
  auto u64_ty = llvm::Type::getInt64Ty(context);
  auto ptr_ty = llvm::Type::getInt64PtrTy(context);
  auto f64_ty = llvm::Type::getDoubleTy(context);
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
  /* void print_addr(uint8_t *arena_ptr, RuntimeManager *rt_m, uint64_t inst_addr, uint64_t func_addr) */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {ptr_ty, ptr_ty, u64_ty, u64_ty}, false),
                         extern_link, "print_addr", *module);
  /* void debug_llvmir_f64vaule(double val) */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {f64_ty}, false), extern_link,
                         debug_llvmir_f64value_name, *module);
  /* void debug_call_stack_push() */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {rt_m_ty, u64_ty}, false), extern_link,
                         debug_call_stack_push_name, *module);
  /* void debug_call_stack_pop() */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {rt_m_ty, u64_ty}, false), extern_link,
                         debug_call_stack_pop_name, *module);
  // void debug_memory_value_change(uint8_t *arena_ptr, RuntimeManager *rt_m, uint64_t pc)
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {ptr_ty, rt_m_ty, u64_ty}, false),
                         extern_link, debug_memory_value_change_name, *module);
  // void debug_memory_value(uint8_t *arena_ptr, RuntimeManager *rt_m)
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {ptr_ty, rt_m_ty}, false), extern_link,
                         debug_memory_value_name, *module);
  /* void debug_insn() */
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {}, false), extern_link, debug_insn_name,
                         *module);
  // void debug_reach()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {}, false), extern_link, debug_reach_name,
                         *module);
  // void debug_string()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {ptr_ty, ptr_ty, u64_ty}, false),
                         extern_link, debug_string_name, *module);
  // void debug_vma_and_registers()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {u64_ty, u64_ty}, true), extern_link,
                         debug_vma_and_registers_name, *module);
  // void debug_check_state_with_qemu()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {rt_m_ty, u64_ty}, true), extern_link,
                         "debug_check_state_with_qemu", *module);
  // void debug_gprs_nzcv()
  llvm::Function::Create(llvm::FunctionType::get(void_ty, {u64_ty}, true), extern_link,
                         "debug_gprs_nzcv", *module);
  return nullptr;
}

void MainLifter::WrapImpl::SetRegisterDebugNames() {
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
  // ECV_NZCV
  auto ecv_nzcv_name_val = llvm::ConstantDataArray::getString(context, "ECV_NZCV", true);
  new llvm::GlobalVariable(*module, ecv_nzcv_name_val->getType(), true,
                           llvm::GlobalVariable::ExternalLinkage, ecv_nzcv_name_val,
                           "debug_ECV_NZCV");
  // SP
  auto ecv_sp_name_val = llvm::ConstantDataArray::getString(context, "SP", true);
  new llvm::GlobalVariable(*module, ecv_sp_name_val->getType(), true,
                           llvm::GlobalVariable::ExternalLinkage, ecv_sp_name_val, "debug_SP");
}

/* Set lifted function symbol name table */
llvm::GlobalVariable *MainLifter::WrapImpl::SetFuncSymbolNameTable(
    std::unordered_map<uint64_t, const char *> &addr_fn_name_map) {

  std::vector<llvm::Constant *> func_symbol_ptr_list, fn_vma_list;

  for (auto &[fn_addr, symbol_name] : addr_fn_name_map) {
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

  // Add guard
  func_symbol_ptr_list.emplace_back(func_symbol_ptr_list[0]);
  fn_vma_list.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), 0xFFFFFFFF));

  SetGblArrayIr(llvm::Type::getInt8PtrTy(context), func_symbol_ptr_list,
                /* "_ecv_fn_symbol_table" */ ecv_fun_symbol_table_name);
  return SetGblArrayIr(llvm::Type::getInt64Ty(context), fn_vma_list,
                       /* "_ecv_fn_debug_vmas" */ ecv_fn_debug_vmas_name);
}
