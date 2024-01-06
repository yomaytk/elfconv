#include "TestState.h"
#include "front/Util.h"
#include "front/elfconv.h"
#include "remill/Arch/AArch64/Runtime/State.h"

#include <map>

extern State g_state;
extern std::map<uint64_t, TestInstructionState> g_disasm_funcs;

extern "C" void get_failed_lifting_detail() {
  auto failed_inst_vma = g_state.gpr.pc.qword;
  if (1 == g_disasm_funcs.count(failed_inst_vma)) {
    auto test_inst_state = g_disasm_funcs[failed_inst_vma];
    printf("[TEST FAIELD] inst_vma: 0x%llx\n", failed_inst_vma);
    printf("Expected: ");
    for (auto &[mname, required] : test_inst_state.required_state)
      printf("%s: %lld", mname.c_str(), required);
    printf("\n");
    printf("Actual:\n");
    debug_state_machine();
    exit(EXIT_FAILURE);
  } else {
    elfconv_runtime_error("%lld is not included in g_disasm_funcs at %s.\n", failed_inst_vma,
                          __func__);
  }
}

extern "C" void show_test_target_insn() {
  auto test_inst_vma = g_state.gpr.pc.qword;
  if (1 == g_disasm_funcs.count(test_inst_vma))
    printf("\"%s\" Test Start.\n", g_disasm_funcs[test_inst_vma].mnemonic.c_str());
  else
    elfconv_runtime_error("%lld is not included in g_disasm_funcs at %s.\n", test_inst_vma,
                          __func__);
}
