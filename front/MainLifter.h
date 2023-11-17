#pragma once

#include "remill/BC/TraceLifter.h"
#include "Binary/Loader.h"

using namespace remill;

class MainLifter final : public TraceLifter {

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
      debug_state_machine_name("debug_state_machine") {}

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
  };

  public:
    inline MainLifter(const Arch *arch_, TraceManager *manager_)
      : TraceLifter(static_cast<TraceLifter::Impl*>(new WrapImpl(arch_, manager_))) {} 
    
    void SetEntryPoint(std::string &entry_func_name);
    void SetEntryPC(uint64_t pc);
    void SetDataSections(std::vector<BinaryLoader::ELFSection> &sections);
    void DefinePreReferedFunction(std::string sub_func_name, std::string lifted_func_name, LLVMFunTypeIdent llvm_fn_ty_id);
    void SetELFPhdr(uint64_t e_phent, uint64_t e_phnum, uint8_t *e_ph);
    void SetPlatform(const char *platform_name);
    void SetLiftedFunPtrTable(std::unordered_map<uint64_t, const char *> &addr_fn_map);
    /* debug */
    void SetControlFlowDebugList(std::unordered_map<uint64_t, bool> &control_flow_debug_list);
    void DeclareDebugStateMachine();
    void DeclareDebugPC();

  private:
    MainLifter(void) = delete;
};
