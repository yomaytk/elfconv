#pragma once

#include "Binary/Loader.h"
#include "remill/BC/TraceLifter.h"

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
          g_addr_list_name("__g_fn_vmas"),
          g_fun_ptr_table_name("__g_fn_ptr_table"),
          g_block_address_ptrs_array_name("__g_block_address_ptrs_array"),
          g_block_address_vmas_array_name("__g_block_address_vmas_array"),
          g_block_address_size_array_name("__g_block_address_size_array"),
          g_block_address_fn_vma_array_name("__g_block_address_fn_vma_array"),
          g_block_address_array_size_name("__g_block_address_array_size"),
          g_fun_symbol_table_name("__g_fn_symbol_table"),
          g_addr_list_second_name("__g_fn_vmas_second"),
          debug_state_machine_name("debug_state_machine"),
          debug_state_machine_vectors_name("debug_state_machine_vectors") {}

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
    std::string g_addr_list_name;
    std::string g_fun_ptr_table_name;
    std::string g_block_address_ptrs_array_name;
    std::string g_block_address_vmas_array_name;
    std::string g_block_address_size_array_name;
    std::string g_block_address_fn_vma_array_name;
    std::string g_block_address_array_size_name;
    std::string g_fun_symbol_table_name;
    std::string g_addr_list_second_name;
    std::string debug_state_machine_name;
    std::string debug_state_machine_vectors_name;

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
    llvm::GlobalVariable *
    SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fun_map);

    /* Set block address data */
    llvm::GlobalVariable *
    SetBlockAddressData(std::vector<llvm::Constant *> &block_address_ptrs_array,
                        std::vector<llvm::Constant *> &block_address_vmas_array,
                        std::vector<llvm::Constant *> &block_address_size_array,
                        std::vector<llvm::Constant *> &block_address_fn_vma_array);

    /* Global variable array definition helper */
    llvm::GlobalVariable *GenGlobalArrayHelper(
        llvm::Type *elem_type, std::vector<llvm::Constant *> &constant_array,
        const llvm::Twine &Name = "", bool isConstant = true,
        llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage) override;

    /* Declare global helper function called by lifted llvm bitcode */
    virtual void DeclareHelperFunction() override;

    /* instruction test helper */
    /* Prepare the virtual machine for instruction test (need override) */
    llvm::BasicBlock *PreVirtualMachineForInsnTest(uint64_t, TraceManager &,
                                                   llvm::BranchInst *) override;
    /* Check the virtual machine for instruction test (need override) */
    llvm::BranchInst *CheckVirtualMahcineForInsnTest(uint64_t, TraceManager &) override;
    /* add L_test_failed (need override) */
    void AddTestFailedBlock() override;

    /* debug helper */
    /* Set control flow debug list */
    void SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &__control_flow_debug_list);
    /* Declare debug function */
    llvm::Function *DeclareDebugFunction();
    /* Set lifted function symbol name table */
    llvm::GlobalVariable *
    SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_map);
  };

 public:
  inline MainLifter(const Arch *arch_, TraceManager *manager_)
      : TraceLifter(static_cast<TraceLifter::Impl *>(new WrapImpl(arch_, manager_))) {}

  /* called derived class */
  MainLifter(WrapImpl *__wrap_impl) : TraceLifter(static_cast<TraceLifter::Impl *>(__wrap_impl)) {}

  void SetEntryPoint(std::string &entry_func_name);
  void SetEntryPC(uint64_t pc);
  void SetDataSections(std::vector<BinaryLoader::ELFSection> &sections);
  void SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph);
  void SetPlatform(const char *platform_name);
  void SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_map);
  void SetBlockAddressData(std::vector<llvm::Constant *> &block_address_ptrs_array,
                           std::vector<llvm::Constant *> &block_address_vmas_array,
                           std::vector<llvm::Constant *> &block_address_size_array,
                           std::vector<llvm::Constant *> &block_address_fn_vma_array);
  virtual void DeclareHelperFunction();
  /* debug */
  void SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &control_flow_debug_list);
  void DeclareDebugFunction();
  void SetFuncSymbolNameTable(std::unordered_map<uint64_t, const char *> &addr_fn_map);

 private:
  MainLifter(void) = delete;
};
