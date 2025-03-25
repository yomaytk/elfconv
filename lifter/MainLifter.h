#pragma once

#include "Binary/Loader.h"

#include <llvm/IR/Constant.h>
#include <remill/BC/TraceLifter.h>

using namespace remill;

class MainLifter : public TraceLifter {
 protected:
  class WrapImpl : public TraceLifter::Impl {
   public:
    WrapImpl(const Arch *__arch, TraceManager *__manager)
        : TraceLifter::Impl(__arch, __manager),
          /* these symbols are declared or defined in the lifted LLVM bitcode */
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
          g_block_address_ptrs_array_name("__g_block_address_ptrs_array"),
          g_block_address_vmas_array_name("__g_block_address_vmas_array"),
          g_block_address_size_array_name("__g_block_address_size_array"),
          g_block_address_fn_vma_array_name("__g_block_address_fn_vma_array"),
          g_block_address_array_size_name("__g_block_address_array_size"),
          g_fun_symbol_table_name("__g_fn_symbol_table"),
          g_addr_list_second_name("__g_fn_vmas_second"),
          ecv_noopt_inst_vmas_name("_ecv_noopt_inst_vmas"),
          ecv_noopt_bb_ptrs_name("_ecv_noopt_bb_ptrs"),
          debug_state_machine_name("debug_state_machine"),
          debug_state_machine_vectors_name("debug_state_machine_vectors"),
          debug_llvmir_u64value_name("debug_llvmir_u64value"),
          debug_llvmir_f64value_name("debug_llvmir_f64value"),
          debug_memory_value_name("debug_memory_value"),
          debug_reach_name("debug_reach"),
          debug_string_name("debug_string"),
          debug_vma_and_registers_name("debug_vma_and_registers") {}

    virtual ~WrapImpl() override {}

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
    std::string g_block_address_ptrs_array_name;
    std::string g_block_address_vmas_array_name;
    std::string g_block_address_size_array_name;
    std::string g_block_address_fn_vma_array_name;
    std::string g_block_address_array_size_name;
    std::string g_fun_symbol_table_name;
    std::string g_addr_list_second_name;
    std::string ecv_noopt_inst_vmas_name;
    std::string ecv_noopt_bb_ptrs_name;

    std::string debug_state_machine_name;
    std::string debug_state_machine_vectors_name;
    std::string debug_llvmir_u64value_name;
    std::string debug_llvmir_f64value_name;
    std::string debug_memory_value_name;
    std::string debug_reach_name;
    std::string debug_string_name;
    std::string debug_vma_and_registers_name;

    // Set RuntimeManager class to global context
    void SetRuntimeManagerClass();

    // Set entry function pointer
    llvm::GlobalVariable *SetEntryPoint(std::string &entry_func_name);

    // Set entry PC
    llvm::GlobalVariable *SetEntryPC(uint64_t pc);

    // Set data sections
    llvm::GlobalVariable *SetDataSections(std::vector<BinaryLoader::ELFSection> &sections);

    /* Set ELF program header info */
    llvm::GlobalVariable *SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph);

    /* Set platform name */
    llvm::GlobalVariable *SetPlatform(const char *platform_name);

    /* Set lifted function pointer table */
    void SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fun_map);

    void SetLiftedNoOptFunPtrTable(std::unordered_map<uint64_t, std::string> &addr_fun_map,
                                   bool is_stripped);

    /* Set block address data */
    void SetBlockAddressData(std::vector<llvm::Constant *> &block_address_ptrs_array,
                             std::vector<llvm::Constant *> &block_address_vmas_array,
                             std::vector<llvm::Constant *> &block_address_size_array,
                             std::vector<llvm::Constant *> &block_address_fn_vma_array);

    /* Global variable array definition helper */
    llvm::GlobalVariable *SetGblArrayIr(
        llvm::Type *elem_type, std::vector<llvm::Constant *> &constant_array,
        const llvm::Twine &Name = "", bool isConstant = true,
        llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage) override;

    /* Declare global helper function called by lifted llvm bitcode */
    virtual void DeclareHelperFunction() override;

    void SetNoOptVmaBBLists(std::vector<std::pair<uint64_t, llvm::Constant *>> noopt_all_vma_bbs,
                            bool is_stripped);
    void SetStrippedFlag(bool is_stripped);

    /* instruction test helper */
    /* Prepare the virtual machine for instruction test (need override) */
    llvm::BasicBlock *PreVirtualMachineForInsnTest(uint64_t, TraceManager &,
                                                   llvm::BranchInst *) override;
    /* Check the virtual machine for instruction test (need override) */
    llvm::BranchInst *CheckVirtualMahcineForInsnTest(uint64_t, TraceManager &) override;
    /* add L_test_failed (need override) */
    void AddTestFailedBlock() override;

    /* debug helper */
    /* Declare debug function */
    llvm::Function *DeclareDebugFunction();
    /* Set lifted function symbol name table */
    llvm::GlobalVariable *
    SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_name_map);
    // set register name gvar
    void SetRegisterNames();
  };

 public:
  inline MainLifter(const Arch *arch_, TraceManager *manager_)
      : TraceLifter(static_cast<TraceLifter::Impl *>(new WrapImpl(arch_, manager_))) {}

  /* called derived class */
  MainLifter(WrapImpl *__wrap_impl) : TraceLifter(static_cast<TraceLifter::Impl *>(__wrap_impl)) {}

  void SetRuntimeManagerClass();
  void SetEntryPoint(std::string &entry_func_name);
  void SetEntryPC(uint64_t pc);
  void SetDataSections(std::vector<BinaryLoader::ELFSection> &sections);
  void SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph);
  void SetPlatform(const char *platform_name);
  void SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_name_map);
  void SetLiftedNoOptFunPtrTable(std::unordered_map<uint64_t, std::string> &addr_fn_name_map,
                                 bool is_stripped);
  void SetBlockAddressData(std::vector<llvm::Constant *> &block_address_ptrs_array,
                           std::vector<llvm::Constant *> &block_address_vmas_array,
                           std::vector<llvm::Constant *> &block_address_size_array,
                           std::vector<llvm::Constant *> &block_address_fn_vma_array);

  virtual void DeclareHelperFunction();

  void Optimize();

  void SetNoOptVmaBBLists(bool is_stripped);
  void SetStrippedFlag(bool is_stripped);
  /* debug */
  void DeclareDebugFunction();
  void SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_name_map);
  void SetRegisterNames();

 private:
  MainLifter(void) = delete;
};
