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
          ecv_entry_func_name("_ecv_entry_func"),
          ecv_entry_pc_name("_ecv_entry_pc"),
          ecv_data_sec_name_array_name("_ecv_data_sec_name_ptr_array"),
          ecv_data_sec_vma_array_name("_ecv_data_sec_vma_array"),
          ecv_data_sec_size_array_name("_ecv_data_sec_size_array"),
          ecv_data_sec_bytes_array_name("_ecv_data_sec_bytes_ptr_array"),
          ecv_data_sec_num_name("_ecv_data_sec_num"),
          ecv_e_phent_name("_ecv_e_phent"),
          ecv_e_phnum_name("_ecv_e_phnum"),
          ecv_e_ph_name("_ecv_e_ph"),
          ecv_platform_name("_ecv_platform_name"),
          ecv_block_address_ptrs_array_name("_ecv_block_address_ptrs_array"),
          ecv_block_address_vmas_array_name("_ecv_block_address_vmas_array"),
          ecv_block_address_size_array_name("_ecv_block_address_size_array"),
          ecv_block_address_fn_vma_array_name("_ecv_block_address_fn_vma_array"),
          ecv_block_address_array_size_name("_ecv_block_address_array_size"),
          ecv_fun_symbol_table_name("_ecv_fn_symbol_table"),
          ecv_addr_list_second_name("_ecv_fn_vmas_second"),
          debug_state_machine_name("debug_state_machine"),
          debug_state_machine_vectors_name("debug_state_machine_vectors"),
          debug_llvmir_u64value_name("debug_llvmir_u64value"),
          debug_llvmir_f64value_name("debug_llvmir_f64value"),
          debug_memory_value_name("debug_memory_value"),
          debug_reach_name("debug_reach"),
          debug_string_name("debug_string"),
          debug_vma_and_registers_name("debug_vma_and_registers") {}

    virtual ~WrapImpl() override {}

    std::string ecv_entry_func_name;
    std::string ecv_entry_pc_name;
    std::string ecv_data_sec_name_array_name;
    std::string ecv_data_sec_vma_array_name;
    std::string ecv_data_sec_size_array_name;
    std::string ecv_data_sec_bytes_array_name;
    std::string ecv_data_sec_num_name;
    std::string ecv_e_phent_name;
    std::string ecv_e_phnum_name;
    std::string ecv_e_ph_name;
    std::string ecv_platform_name;
    std::string ecv_block_address_ptrs_array_name;
    std::string ecv_block_address_vmas_array_name;
    std::string ecv_block_address_size_array_name;
    std::string ecv_block_address_fn_vma_array_name;
    std::string ecv_block_address_array_size_name;
    std::string ecv_fun_symbol_table_name;
    std::string ecv_addr_list_second_name;

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

    // Set entry point pointer of the lifted function
    llvm::GlobalVariable *SetEntryPoint(std::string &entry_func_name);

    // Set entry PC
    llvm::GlobalVariable *SetEntryPC(uint64_t pc);

    // Set data sections
    llvm::GlobalVariable *SetDataSections(std::vector<BinaryLoader::ELFSection> &sections);

    //  Set ELF program header info
    llvm::GlobalVariable *SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph);

    //  Set target platform name
    llvm::GlobalVariable *SetPlatform(const char *platform_name);

    //  Set lifted function pointer table
    void SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fun_map);

    void SetLiftedNoOptFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fun_map,
                                   bool is_stripped);

    // Set block address data
    void SetBlockAddressData(std::vector<llvm::Constant *> &block_address_ptrs_array,
                             std::vector<llvm::Constant *> &block_address_vmas_array,
                             std::vector<llvm::Constant *> &block_address_size_array,
                             std::vector<llvm::Constant *> &block_address_fn_vma_array);

    //  Global variable array definition helper function
    llvm::GlobalVariable *SetGblArrayIr(
        llvm::Type *elem_type, std::vector<llvm::Constant *> &constant_array,
        const llvm::Twine &Name = "", bool isConstant = true,
        llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage) override;

    // `__g_get_jmp_block_address(RuntimeManager*, uint64_t, uint64_t)`
    // `uint64_t *_ecv_noopt_get_bb(RuntimeManager *, addr_t)`
    virtual void DeclareHelperFunction() override;

    void SetNoOptVmaBBLists(std::vector<std::pair<uint64_t, llvm::Constant *>> noopt_all_vma_bbs,
                            bool is_stripped);
    void SetStrippedFlag(bool is_stripped);

    //  instruction test helper
    //  Prepare the virtual machine for instruction test (need override)
    llvm::BasicBlock *PreVirtualMachineForInsnTest(uint64_t, TraceManager &,
                                                   llvm::BranchInst *) override;
    //  Check the virtual machine for instruction test (need override)
    llvm::BranchInst *CheckVirtualMahcineForInsnTest(uint64_t, TraceManager &) override;
    //  Add L_test_failed (need override)
    void AddTestFailedBlock() override;

    /* Debug */
    //  Declare debug function
    llvm::Function *DeclareDebugFunction();
    //  Set lifted function symbol name table
    llvm::GlobalVariable *
    SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_name_map);
    // set register name gvar
    void SetRegisterDebugNames();
  };

 public:
  inline MainLifter(const Arch *arch_, TraceManager *manager_)
      : TraceLifter(static_cast<TraceLifter::Impl *>(new WrapImpl(arch_, manager_))) {}

  //  Called derived class
  MainLifter(WrapImpl *__wrap_impl) : TraceLifter(static_cast<TraceLifter::Impl *>(__wrap_impl)) {}


  void SetRuntimeManagerClass();
  void SetEntryPoint(std::string &entry_func_name);
  void SetEntryPC(uint64_t pc);
  void SetDataSections(std::vector<BinaryLoader::ELFSection> &sections);
  void SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph);
  void SetPlatform(const char *platform_name);
  void SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_name_map);
  void SetLiftedNoOptFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_name_map,
                                 bool is_stripped);
  void SetBlockAddressData(std::vector<llvm::Constant *> &block_address_ptrs_array,
                           std::vector<llvm::Constant *> &block_address_vmas_array,
                           std::vector<llvm::Constant *> &block_address_size_array,
                           std::vector<llvm::Constant *> &block_address_fn_vma_array);
  virtual void DeclareHelperFunction();

  void Optimize();

  // Set all addressses of the basic blocks of the every instruction for noopt lifted functions.
  void SetNoOptVmaBBLists(bool is_stripped);
  // Set stripped flag `_ecv_is_stripped`.
  void SetStrippedFlag(bool is_stripped);

  // Set common metadata of the ELF whether it is stripped or not.
  void SetCommonMetaData();

  void SubseqOfLifting(std::unordered_map<uint64_t, const char *> &addr_opt_fun_name_map);
  void SubseqForNoOptLifting(std::unordered_map<uint64_t, const char *> &addr_noopt_fun_name_map);

  /* Debug */
  // Declare debug function
  void DeclareDebugFunction();
  void SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_name_map);
  void SetRegisterDebugNames();

 private:
  MainLifter(void) = delete;
};
