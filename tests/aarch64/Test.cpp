#include "Test.h"

#include "front/Memory.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/BC/HelperMacro.h"

#include <cstdint>
#include <cstring>
#include <map>
#include <stdio.h>

State g_state = State();
RuntimeManager *g_run_mgr;
extern LiftedFunc aarch64_insn_test_main_func;

int main(int argc, char *argv[]) {

  std::vector<MappedMemory *> mapped_memorys;

  /* allocate Stack */
  mapped_memorys.push_back(MappedMemory::VMAStackEntryInit(argc, argv, &g_state));
  /* allocate Heap */
  mapped_memorys.push_back(MappedMemory::VMAHeapEntryInit());
  /* set program counter */
  g_state.gpr.pc = {.qword = __g_entry_pc};
  /* set system register (FIXME) */
  g_state.sr.tpidr_el0 = {.qword = 0};
  g_state.sr.midr_el1 = {.qword = 0xf0510};
  g_state.sr.ctr_el0 = {.qword = 0x80038003};
  g_state.sr.dczid_el0 = {.qword = 0x4};
  /* set global RuntimeManager */
  g_run_mgr = new RuntimeManager(mapped_memorys);
  g_run_mgr->heaps_end_addr = HEAPS_START_VMA + HEAP_SIZE;
  /* set lifted function pointer table */
  for (int i = 0; __g_fn_vmas[i] && __g_fn_ptr_table[i]; i++) {
    g_run_mgr->addr_fn_map[__g_fn_vmas[i]] = __g_fn_ptr_table[i];
  }
  /* go to the aarch64_insn_test_main_func */
  aarch64_insn_test_main_func(&g_state, __g_entry_pc, reinterpret_cast<Memory *>(g_run_mgr));

  delete (g_run_mgr);

  return 0;
}
