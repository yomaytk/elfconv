#pragma once

#include "front/MainLifter.h"

class TestLifter final : public MainLifter {
  class TestWrapImpl final : public MainLifter::WrapImpl {
   public:
    TestWrapImpl(const Arch *__arch, TraceManager *__manager)
        : MainLifter::WrapImpl(__arch, __manager),
          pre_vm_bb_name("L_pre_vm"),
          check_vm_bb_name("L_check_vm"),
          test_failed_bb_name("L_test_failed"),
          test_failed_result_fn_name("get_failed_lifting_detail"),
          show_test_target_inst_name("show_test_target_insn"),
          unique_num_of_bb(0),
          test_failed_block(nullptr) {}

    ~TestWrapImpl() final {}

    /* Prepare the virtual machine for instruction test (need override) */
    llvm::BasicBlock *PreVirtualMachineForInsnTest(uint64_t inst_addr, TraceManager &trace_manager,
                                                   llvm::BranchInst *pre_check_branch_inst) final;
    /* Check the virtual machine for instruction test (need override) */
    llvm::BranchInst *CheckVirtualMahcineForInsnTest(uint64_t inst_addr,
                                                     TraceManager &trace_manager) final;
    void AddTestFailedBlock() final;
    void DeclareHelperFunction() final;

    inline std::string GetUniquePreVMBBName();
    inline std::string GetUniqueCheckVMBBName();

   public:
    std::string pre_vm_bb_name;
    std::string check_vm_bb_name;
    std::string test_failed_bb_name;
    std::string test_failed_result_fn_name;
    std::string show_test_target_inst_name;
    uint32_t unique_num_of_bb;

    llvm::BasicBlock *test_failed_block;
  };

 public:
  TestLifter(const Arch *__arch, TraceManager *__manager)
      : MainLifter(static_cast<MainLifter::WrapImpl *>(new TestWrapImpl(__arch, __manager))) {}

  void DeclareHelperFunction() final;
};
