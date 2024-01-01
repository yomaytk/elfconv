#pragma once
#include "front/Lift.h"
#include "front/MainLifter.h"
#include "front/Memory.h"
#include "front/TraceManager.h"

#include <cstddef>
#include <cstdint>

static const uintptr_t g_test_disasm_func_vma = 0x00400000;

class DisassembleCmd {
 public:
  static void ExecRasm2(const std::string &nemonic, uint8_t insn_bytes[4]);
};

class TestInstructionState {
 public:
  std::string mnemonic;
  std::unordered_map<std::string, uint64_t> ini_state;
  std::unordered_map<std::string, uint64_t> required_state;

  TestInstructionState(std::string __mnemonic,
                       std::unordered_map<std::string, uint64_t> __ini_state,
                       std::unordered_map<std::string, uint64_t> __required_state)
      : mnemonic(__mnemonic),
        ini_state(__ini_state),
        required_state(__required_state) {}
};

class TestAArch64TraceManager final : public AArch64TraceManager {
 public:
  TestAArch64TraceManager(std::string __target_elf_file_name)
      : AArch64TraceManager(__target_elf_file_name){};
  std::unordered_map<uint64_t, TestInstructionState *> test_inst_state_map;
};

class TestLifter final : public MainLifter {
  class TestWrapImpl : public MainLifter::WrapImpl {
   public:
    TestWrapImpl(const Arch *__arch, TraceManager *__manager)
        : MainLifter::WrapImpl(__arch, __manager),
          pre_vm_bb_name("L_pre_vm"),
          check_vm_bb_name("L_check_vm"),
          test_failed_bb_name("L_test_failed"),
          test_failed_result_fn_name("debug_state_machine"),
          unique_num_of_bb(0),
          test_failed_block(nullptr) {}

    /* Prepare the virtual machine for instruction test (need override) */
    llvm::BasicBlock *PreVirtualMachineForInsnTest(uint64_t inst_addr, TraceManager &trace_manager,
                                                   llvm::BranchInst *pre_check_branch_inst) final;
    /* Check the virtual machine for instruction test (need override) */
    llvm::BranchInst *CheckVirtualMahcineForInsnTest(uint64_t inst_addr,
                                                     TraceManager &trace_manager) final;
    void AddTestFailedBlock() final;
    inline std::string GetUniquePreVMBBName();
    inline std::string GetUniqueCheckVMBBName();

   public:
    std::string pre_vm_bb_name;
    std::string check_vm_bb_name;
    std::string test_failed_bb_name;
    std::string test_failed_result_fn_name;
    uint32_t unique_num_of_bb;

    llvm::BasicBlock *test_failed_block;
  };

 public:
  TestLifter(const Arch *__arch, TraceManager *__manager)
      : MainLifter(static_cast<MainLifter::WrapImpl *>(new TestWrapImpl(__arch, __manager))) {}
};
