#include "Memory.h"

#include <cstdint>
#include <cstring>
#include <remill/BC/HelperMacro.h>
#if defined(LIFT_DEBUG)
#  include <signal.h>
#  include <utils/Util.h>
#  include <utils/elfconv.h>
#endif
#include <iostream>
#include <map>
#include <remill/Arch/AArch64/Runtime/State.h>
#include <remill/Arch/Runtime/Intrinsics.h>
#include <remill/BC/HelperMacro.h>
#include <stdio.h>

State g_state = State();
RuntimeManager *g_run_mgr;

int main(int argc, char *argv[]) {

  std::vector<MappedMemory *> mapped_memorys;

#if defined(LIFT_DEBUG)
  struct sigaction segv_action = {0};
  segv_action.sa_flags = SA_SIGINFO;
  segv_action.sa_sigaction = segv_debug_state_machine;
  if (sigaction(SIGSEGV, &segv_action, NULL) < 0)
    elfconv_runtime_error("sigaction for SIGSEGV failed.\n");
#endif

  /* allocate Stack */
  auto mapped_stack = MappedMemory::VMAStackEntryInit(argc, argv, &g_state);
  /* allocate Heap */
  auto mapped_heap = MappedMemory::VMAHeapEntryInit();
  /* allocate every sections */
  for (int i = 0; i < __g_data_sec_num; i++) {
    // remove covered section (FIXME)
    if (strncmp(reinterpret_cast<const char *>(__g_data_sec_name_ptr_array[i]), ".tbss", 5) == 0)
      continue;
    mapped_memorys.push_back(new MappedMemory(
        MemoryAreaType::DATA, reinterpret_cast<const char *>(__g_data_sec_name_ptr_array[i]),
        __g_data_sec_vma_array[i],
        __g_data_sec_vma_array[i] + static_cast<size_t>(__g_data_sec_size_array[i]),
        static_cast<size_t>(__g_data_sec_size_array[i]), __g_data_sec_bytes_ptr_array[i],
        __g_data_sec_bytes_ptr_array[i] + __g_data_sec_size_array[i], false));
  }
  /* set program counter */
  g_state.gpr.pc = {.qword = __g_entry_pc};
  /* set system register (FIXME) */
  g_state.sr.tpidr_el0 = {.qword = 0};
  g_state.sr.midr_el1 = {.qword = 0xf0510};
  g_state.sr.ctr_el0 = {.qword = 0x80038003};
  g_state.sr.dczid_el0 = {.qword = 0x4};
  /* set global RuntimeManager */
  g_run_mgr = new RuntimeManager(mapped_memorys, mapped_stack, mapped_heap);
  g_run_mgr->heaps_end_addr = HEAPS_START_VMA + HEAP_UNIT_SIZE;
  /* set lifted function pointer table */
  for (int i = 0; __g_fn_vmas[i] && __g_fn_ptr_table[i]; i++) {
    g_run_mgr->addr_fn_map[__g_fn_vmas[i]] = __g_fn_ptr_table[i];
  }
#if defined(LIFT_CALLSTACK_DEBUG)
  /* set lifted function symbol table (for debug) */
  for (int i = 0; __g_fn_vmas_second[i] && __g_fn_symbol_table[i]; i++) {
    g_run_mgr->addr_fn_symbol_map[__g_fn_vmas_second[i]] = (const char *) __g_fn_symbol_table[i];
  }
#endif
  /* set global block address data array */
  for (int i = 0; i < __g_block_address_array_size; i++) {
    auto bb_num = __g_block_address_size_array[i];
    std::map<uint64_t, uint64_t *> vma_bb_map;
    auto t_block_address_ptrs = __g_block_address_ptrs_array[i];
    auto t_block_address_vmas = __g_block_address_vmas_array[i];
    for (int j = 0; j < bb_num; j++)
      vma_bb_map[t_block_address_vmas[j]] = t_block_address_ptrs[j];
    g_run_mgr->addr_block_addrs_map[__g_block_address_fn_vma_array[i]] = vma_bb_map;
  }
  /* go to the entry function (entry function is injected by lifted LLVM IR) */
  __g_entry_func(&g_state, __g_entry_pc, nullptr);

  delete (g_run_mgr);

  return 0;
}
